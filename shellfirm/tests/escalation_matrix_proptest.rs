#![cfg(feature = "tui")]

use proptest::prelude::*;
use shellfirm::checks::Severity;
use shellfirm::config::{Challenge, SeverityEscalationConfig, Settings};

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
