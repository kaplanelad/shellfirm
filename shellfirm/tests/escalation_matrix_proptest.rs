#![cfg(feature = "tui")]

use proptest::prelude::*;
use shellfirm::checks::{Check, Severity};
use shellfirm::config::{Challenge, Mode, Settings, SeverityEscalationConfig};
use shellfirm::context::{self, EscalationConfig, RiskLevel, RuntimeContext};
use shellfirm::policy::MergedPolicy;

fn arb_challenge() -> impl Strategy<Value = Challenge> {
    prop_oneof![
        Just(Challenge::Math),
        Just(Challenge::Enter),
        Just(Challenge::Yes)
    ]
}

fn arb_severity() -> impl Strategy<Value = Severity> {
    prop_oneof![
        Just(Severity::Info),
        Just(Severity::Low),
        Just(Severity::Medium),
        Just(Severity::High),
        Just(Severity::Critical),
    ]
}

proptest! {
    #[test]
    fn severity_escalation_round_trips_via_yaml(
        critical in arb_challenge(),
        high in arb_challenge(),
        medium in arb_challenge(),
        low in arb_challenge(),
        info in arb_challenge(),
        enabled: bool,
    ) {
        let mut s = Settings::default();
        s.severity_escalation = SeverityEscalationConfig {
            enabled, critical, high, medium, low, info,
        };
        let yaml = serde_yaml::to_string(&s).unwrap();
        let parsed: Settings = serde_yaml::from_str(&yaml).unwrap();
        prop_assert_eq!(parsed.severity_escalation.critical, critical);
        prop_assert_eq!(parsed.severity_escalation.high, high);
        prop_assert_eq!(parsed.severity_escalation.medium, medium);
        prop_assert_eq!(parsed.severity_escalation.low, low);
        prop_assert_eq!(parsed.severity_escalation.info, info);
        prop_assert_eq!(parsed.severity_escalation.enabled, enabled);
    }

    #[test]
    fn severity_escalation_challenge_for_severity_returns_correct_challenge(
        critical in arb_challenge(),
        high in arb_challenge(),
        medium in arb_challenge(),
        low in arb_challenge(),
        info in arb_challenge(),
        sev in arb_severity(),
    ) {
        let cfg = SeverityEscalationConfig {
            enabled: true, critical, high, medium, low, info,
        };
        let result = cfg.challenge_for_severity(sev);
        let expected = match sev {
            Severity::Critical => critical,
            Severity::High => high,
            Severity::Medium => medium,
            Severity::Low => low,
            Severity::Info => info,
        };
        prop_assert_eq!(result, Some(expected));
    }

    #[test]
    fn severity_escalation_disabled_returns_none(
        critical in arb_challenge(),
        high in arb_challenge(),
        medium in arb_challenge(),
        low in arb_challenge(),
        info in arb_challenge(),
        sev in arb_severity(),
    ) {
        let cfg = SeverityEscalationConfig {
            enabled: false, critical, high, medium, low, info,
        };
        prop_assert!(cfg.challenge_for_severity(sev).is_none());
    }
}

// ---------------------------------------------------------------------------
// Escalation monotonicity: every layer is a floor, nothing ever lowers the
// challenge, and "escalated" is reported only when it actually got stricter.
// ---------------------------------------------------------------------------

fn arb_risk() -> impl Strategy<Value = RiskLevel> {
    prop_oneof![
        Just(RiskLevel::Normal),
        Just(RiskLevel::Elevated),
        Just(RiskLevel::Critical),
    ]
}

fn make_check(severity: Severity) -> Check {
    let yaml = format!(
        "- id: git:force_push\n  from: git\n  test: force\n  description: d\n  severity: {severity:?}\n"
    );
    let mut v: Vec<Check> = serde_yaml::from_str(&yaml).unwrap();
    v.remove(0)
}

proptest! {
    #[test]
    fn challenge_order_is_enter_math_yes(a in arb_challenge(), b in arb_challenge()) {
        let s = a.stricter(b);
        prop_assert!(s >= a && s >= b);
        prop_assert_eq!(s, b.stricter(a));
        prop_assert!(s == a || s == b);
        prop_assert!(Challenge::Enter < Challenge::Math && Challenge::Math < Challenge::Yes);
    }

    #[test]
    fn context_escalation_never_lowers(
        base in arb_challenge(),
        elevated in arb_challenge(),
        critical in arb_challenge(),
        risk in arb_risk(),
    ) {
        let esc = EscalationConfig { elevated, critical };
        let out = context::escalate_challenge(&base, risk, &esc);
        prop_assert!(out >= base);
        match risk {
            RiskLevel::Normal => prop_assert_eq!(out, base),
            RiskLevel::Elevated => prop_assert!(out >= elevated),
            RiskLevel::Critical => prop_assert!(out >= critical),
        }
    }

    #[test]
    fn effective_challenge_is_at_least_every_layer(
        base in arb_challenge(),
        sev in arb_severity(),
        sev_floor in arb_challenge(),
        group_floor in proptest::option::of(arb_challenge()),
        check_floor in proptest::option::of(arb_challenge()),
        policy_floor in proptest::option::of(arb_challenge()),
        elevated in arb_challenge(),
        critical in arb_challenge(),
        ssh: bool,
        on_main: bool,
        root: bool,
    ) {
        let mut settings = Settings {
            challenge: base,
            severity_escalation: SeverityEscalationConfig {
                enabled: true,
                critical: sev_floor,
                high: sev_floor,
                medium: sev_floor,
                low: sev_floor,
                info: sev_floor,
            },
            ..Settings::default()
        };
        if let Some(g) = group_floor {
            settings.group_escalation.insert("git".into(), g);
        }
        if let Some(c) = check_floor {
            settings.check_escalation.insert("git:force_push".into(), c);
        }
        settings.context.escalation = EscalationConfig { elevated, critical };
        let mut policy = MergedPolicy::default();
        if let Some(p) = policy_floor {
            policy.challenge_overrides.insert("git:force_push".into(), p);
        }

        let mut ctx = RuntimeContext {
            is_ssh: ssh,
            is_root: root,
            git_branch: on_main.then(|| "main".to_string()),
            ..Default::default()
        };
        ctx.refresh(&settings.context);

        let check = make_check(sev);
        let resolved = settings.resolved_for(Mode::Shell);
        let eff = context::effective_challenge(&settings, &resolved, &[&check], &ctx, &policy);

        prop_assert_eq!(eff.base, base);
        prop_assert!(eff.challenge >= base);
        prop_assert!(eff.challenge >= sev_floor);
        for f in [group_floor, check_floor, policy_floor].into_iter().flatten() {
            prop_assert!(eff.challenge >= f);
        }
        match ctx.risk_level {
            RiskLevel::Normal => {}
            RiskLevel::Elevated => prop_assert!(eff.challenge >= elevated),
            RiskLevel::Critical => prop_assert!(eff.challenge >= critical),
        }
        // "Escalated" only when it actually got stricter, always with a reason.
        prop_assert_eq!(eff.is_escalated(), eff.challenge > base);
        if eff.is_escalated() {
            prop_assert!(!eff.reasons.is_empty());
            prop_assert!(eff.note().is_some());
        } else {
            prop_assert!(eff.reasons.is_empty());
            prop_assert!(eff.note().is_none());
        }
    }
}
