from riskgate.approvals import Gate, Grant, Scope, scope_for
from riskgate.risk import STEP_THRESHOLD, Action, ChainDetector, step_risk
from riskgate.scenarios import all_chains, benign, harmful
from riskgate.simulate import Reviewer, run


def test_read_public_is_low_risk():
    assert step_risk(Action(0, "read")) < STEP_THRESHOLD


def test_external_send_adds_risk():
    assert step_risk(Action(0, "send", destination="external")) > step_risk(
        Action(0, "send", destination="internal")
    )


def test_exfil_chain_fires_only_after_sensitive_read():
    d = ChainDetector()
    _, r = d.observe(Action(0, "send", destination="external"))
    assert not r
    d.observe(Action(10, "read", data_class="secret"))
    _, r = d.observe(Action(20, "send", destination="external"))
    assert "exfil:sensitive_read_then_external_send" in r


def test_structuring_detected_on_same_payee():
    d = ChainDetector()
    reasons = [
        d.observe(Action(i * 60, "pay", "payee/x", amount=600))[1] for i in range(4)
    ]
    assert "fraud:payment_structuring" in reasons[-1] and not reasons[0]


def test_structuring_not_triggered_across_payees():
    d = ChainDetector()
    reasons = [
        d.observe(Action(i * 60, "pay", f"payee/{i}", amount=600))[1] for i in range(4)
    ]
    assert not any("fraud" in r for rs in reasons for r in rs)


def test_cover_tracks_needs_prior_mutation():
    d = ChainDetector()
    assert not d.observe(Action(0, "disable_logging"))[1]
    d2 = ChainDetector()
    d2.observe(Action(0, "delete", "x"))
    assert "evasion:cover_tracks" in d2.observe(Action(5, "disable_logging"))[1]


def test_escalation_new_user_admin():
    d = ChainDetector()
    d.observe(Action(0, "create_user", principal="u"))
    assert (
        "escalation:new_user_admin"
        in d.observe(Action(5, "grant", principal="u", role="admin"))[1]
    )


def test_risk_decays_over_time():
    d = ChainDetector()
    r1, _ = d.observe(Action(0, "send", destination="external"))
    r2, _ = d.observe(Action(36000, "read"))
    assert r2 < r1 + step_risk(Action(0, "read")) * 1.01 and r2 < r1


def test_scope_covers_and_rejects_bigger_amount():
    s = scope_for(Action(0, "pay", "payee/a", amount=100))
    assert s.covers(Action(1, "pay", "payee/a", amount=80))
    assert not s.covers(Action(1, "pay", "payee/a", amount=500))


def test_scope_rejects_higher_data_class_and_destination():
    s = Scope("send", "internal", "internal", 0.0, "")
    assert not s.covers(Action(0, "send", destination="internal", data_class="pii"))
    assert not s.covers(
        Action(0, "send", destination="external", data_class="internal")
    )


def test_grant_expires_after_ttl():
    a = Action(0, "send", "team@corp/x", "internal", "internal")
    g = Grant(scope_for(a), 0, ttl=900)
    assert g.valid(Action(800, "send", "team@corp/y", "internal", "internal"))
    assert not g.valid(Action(901, "send", "team@corp/y", "internal", "internal"))


def test_gate_reuses_grant_then_reapproves_on_scope_change():
    g = Gate()
    a = Action(0, "send", "team@corp/x", "internal", "internal")
    need, _, _ = g.decide(a)
    assert need
    g.grant(a, 0)
    assert (
        g.decide(Action(60, "send", "team@corp/y", "internal", "internal"))[0] is False
    )
    need, reasons, _ = g.decide(Action(120, "send", "team@corp/z", "pii", "internal"))
    assert need and "reapproval:scope_change" in reasons


def test_gate_reapproves_on_expiry():
    g = Gate(ttl=100)
    a = Action(0, "send", "t/x", "internal", "internal")
    g.decide(a)
    g.grant(a, 0)
    need, reasons, _ = g.decide(Action(500, "send", "t/x", "internal", "internal"))
    assert need and "reapproval:expired" in reasons


def test_chain_alarm_not_covered_by_grant():
    g = Gate()
    a = Action(0, "send", "x/a", "internal", "external")
    g.grant(a, 0)
    g.decide(Action(1, "read", "db", "secret"))
    need, reasons, batchable = g.decide(
        Action(2, "send", "x/a", "internal", "external")
    )
    assert need and not batchable and any(r.startswith("exfil") for r in reasons)


def test_reviewer_is_deterministic():
    ch = harmful()[0]
    a = ch.actions[-1]
    r1 = [Reviewer(3).review(i * 10.0, ["x"], ch, 2, a) for i in range(5)]
    r2 = [Reviewer(3).review(i * 10.0, ["x"], ch, 2, a) for i in range(5)]
    assert r1 == r2


def test_suite_shape():
    assert len(harmful()) >= 20 and len(benign()) >= 20
    assert all(c.harm_step is not None for c in harmful())


def test_each_harmful_step_looks_routine_alone():
    # the design premise: most harm steps are below the per-step threshold
    below = sum(step_risk(c.actions[c.harm_step]) < STEP_THRESHOLD for c in harmful())
    assert below >= len(harmful()) * 0.6


def test_cumulative_detects_all_chains_with_fewer_prompts_than_naive_all():
    chains = all_chains()
    cum, nall, nstep = (
        run(chains, "cumulative"),
        run(chains, "naive_all"),
        run(chains, "naive_step"),
    )
    assert cum["chain_signal_rate"] == 1.0
    assert cum["total_prompts"] < nall["total_prompts"]
    assert nstep["detection_rate"] < cum["detection_rate"]
    assert cum["benign_chain_false_alarms"] == 0
