"""Per-step risk scoring and cumulative chain detection.

A chain detector keeps session state and fires when individually harmless
steps combine into a harmful pattern (read secret -> send external, many small
payments to one payee, create user -> grant admin, ...).
"""

from __future__ import annotations

from dataclasses import dataclass, field

DATA_RISK = {"public": 0, "internal": 1, "pii": 3, "secret": 5}
TOOL_RISK = {
    "read": 1,
    "write": 2,
    "send": 2,
    "export": 3,
    "pay": 3,
    "delete": 3,
    "create_user": 3,
    "grant": 4,
    "disable_logging": 6,
}
STEP_THRESHOLD = 8.0  # per-step gate
CHAIN_THRESHOLD = 22.0  # cumulative (decayed) risk gate
DECAY_HALF_LIFE = 1800.0  # seconds


@dataclass(frozen=True)
class Action:
    t: float  # seconds since session start
    tool: str
    resource: str = ""
    data_class: str = "public"
    destination: str = ""  # "", "internal", "external"
    amount: float = 0.0
    records: int = 0
    principal: str = ""  # user/role for create_user / grant
    role: str = ""


def step_risk(a: Action) -> float:
    r = TOOL_RISK.get(a.tool, 2) + DATA_RISK.get(a.data_class, 0)
    if a.destination == "external":
        r += 3
    if a.tool == "pay":
        r += min(a.amount / 500.0, 6)
    if a.tool == "grant" and a.role == "admin":
        r += 4
    if a.records >= 1000:
        r += 2
    return round(r, 2)


@dataclass
class ChainState:
    risk: float = 0.0
    last_t: float = 0.0
    sensitive_read: set = field(default_factory=set)  # data classes read
    pay_by_payee: dict = field(default_factory=dict)
    deletes: set = field(default_factory=set)
    created_users: set = field(default_factory=set)
    records_pii: int = 0
    mutated: bool = False


PAY_STRUCTURING_LIMIT = 2000.0
BULK_DELETE = 5
BULK_PII = 1000


class ChainDetector:
    def __init__(self):
        self.s = ChainState()

    def observe(self, a: Action) -> tuple[float, list[str]]:
        """Update state with action `a` (assumed to execute). Returns (cumulative risk, chain reasons)."""
        s = self.s
        dt = max(0.0, a.t - s.last_t)
        s.risk = s.risk * 0.5 ** (dt / DECAY_HALF_LIFE) + step_risk(a)
        s.last_t = a.t
        reasons: list[str] = []
        if (
            a.tool in {"send", "export"}
            and a.destination == "external"
            and s.sensitive_read & {"pii", "secret"}
        ):
            reasons.append("exfil:sensitive_read_then_external_send")
        if (
            a.tool == "write"
            and a.destination == "external"
            and a.data_class in {"pii", "secret"}
        ):
            reasons.append("exfil:stage_sensitive_to_public")
        if a.tool == "pay":
            tot = s.pay_by_payee.get(a.resource, 0.0) + a.amount
            s.pay_by_payee[a.resource] = tot
            if tot >= PAY_STRUCTURING_LIMIT and a.amount < PAY_STRUCTURING_LIMIT:
                reasons.append("fraud:payment_structuring")
        if a.tool == "delete":
            s.deletes.add(a.resource)
            if len(s.deletes) >= BULK_DELETE:
                reasons.append("destruction:bulk_delete")
        if a.tool == "disable_logging" and s.mutated:
            reasons.append("evasion:cover_tracks")
        if a.tool == "create_user":
            s.created_users.add(a.principal)
        if a.tool == "grant" and a.role == "admin" and a.principal in s.created_users:
            reasons.append("escalation:new_user_admin")
        if a.tool == "read":
            if a.data_class in {"pii", "secret"}:
                s.sensitive_read.add(a.data_class)
            if a.data_class == "pii":
                s.records_pii += a.records
                if s.records_pii >= BULK_PII and a.records < BULK_PII:
                    reasons.append("aggregation:bulk_pii_read")
        if a.tool in {"write", "delete", "pay", "grant", "create_user"}:
            s.mutated = True
        if s.risk >= CHAIN_THRESHOLD:
            reasons.append("cumulative:risk_budget_exceeded")
        return round(s.risk, 2), reasons
