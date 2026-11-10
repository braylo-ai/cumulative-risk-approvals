"""Approval engine: scoped grants with TTL, re-approval on scope change, batching.

Three gating policies share one interface:
  naive_all   prompt for every non-read step, one by one
  naive_step  prompt only when the single step's risk >= STEP_THRESHOLD
  cumulative  per-step + chain detectors + scoped/TTL grants + batching (this project)
"""

from __future__ import annotations

from dataclasses import dataclass, field

from .risk import STEP_THRESHOLD, Action, ChainDetector, step_risk

DEFAULT_TTL = 900.0  # seconds an approval stays valid
BATCH_WINDOW = 120.0  # low-risk requests inside this window share one prompt


@dataclass(frozen=True)
class Scope:
    tool: str
    destination: str
    data_class: str
    amount_cap: float
    resource_prefix: str = ""

    def covers(self, a: Action) -> bool:
        order = ["public", "internal", "pii", "secret"]
        return (
            a.tool == self.tool
            and a.destination == self.destination
            and order.index(a.data_class) <= order.index(self.data_class)
            and a.amount <= self.amount_cap
            and a.resource.startswith(self.resource_prefix)
        )


def scope_for(a: Action) -> Scope:
    prefix = a.resource.rsplit("/", 1)[0] + "/" if "/" in a.resource else a.resource
    return Scope(a.tool, a.destination, a.data_class, max(a.amount, 0.0), prefix)


@dataclass
class Grant:
    scope: Scope
    granted_at: float
    ttl: float = DEFAULT_TTL

    def valid(self, a: Action) -> bool:
        return a.t - self.granted_at <= self.ttl and self.scope.covers(a)


@dataclass
class Prompt:
    t: float
    actions: list
    reasons: list
    batched: bool = False


@dataclass
class Gate:
    policy: str = "cumulative"
    ttl: float = DEFAULT_TTL
    grants: list = field(default_factory=list)
    detector: ChainDetector = field(default_factory=ChainDetector)
    open_batch: Prompt | None = None
    stats: dict = field(
        default_factory=lambda: {"reapproval_scope_change": 0, "reapproval_expired": 0}
    )

    def decide(self, a: Action) -> tuple[bool, list[str], bool]:
        """Return (needs_prompt, reasons, batchable). Updates chain state."""
        cum, chain = self.detector.observe(a)
        sr = step_risk(a)
        if self.policy == "naive_all":
            return a.tool != "read", [f"step:{a.tool}"], False
        if self.policy == "naive_step":
            return sr >= STEP_THRESHOLD, [f"step_risk:{sr}"], False
        reasons = list(chain)
        if sr >= STEP_THRESHOLD:
            reasons.append(f"step_risk:{sr}")
        if chain:
            return True, reasons, False  # chain alarms are never batched or pre-covered
        if a.tool == "read" and sr < STEP_THRESHOLD:
            return False, [], False
        # covered by an existing grant?
        for g in self.grants:
            if g.valid(a):
                return False, ["covered_by_grant"], False
        same_scope = [
            g
            for g in self.grants
            if g.scope.tool == a.tool and g.scope.destination == a.destination
        ]
        if same_scope:
            # a grant whose scope still covers the action but whose TTL ran out
            if any(g.scope.covers(a) for g in same_scope):
                self.stats["reapproval_expired"] += 1
                reasons.append("reapproval:expired")
            else:
                self.stats["reapproval_scope_change"] += 1
                reasons.append("reapproval:scope_change")
        if (
            sr < STEP_THRESHOLD - 3
            and a.tool in {"write", "send", "delete", "pay"}
            and a.destination != "external"
        ):
            return True, reasons + ["low_risk_batchable"], True
        return True, reasons or [f"step_risk:{sr}"], False

    def grant(self, a: Action, t: float) -> None:
        if self.policy == "cumulative":
            self.grants.append(Grant(scope_for(a), t, self.ttl))
