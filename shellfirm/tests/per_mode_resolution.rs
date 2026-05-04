use shellfirm::checks::Severity;
use shellfirm::config::{Challenge, InheritOr, Mode, Settings};

#[test]
fn ai_min_severity_override_lowers_threshold() {
    let mut s = Settings::default();
    s.min_severity = Some(Severity::High);
    s.agent.min_severity = InheritOr::Set(Some(Severity::Low));

    let shell = s.resolved_for(Mode::Shell);
    let ai = s.resolved_for(Mode::Ai);

    assert_eq!(shell.min_severity, Some(Severity::High));
    assert_eq!(ai.min_severity, Some(Severity::Low));
}

#[test]
fn wrap_challenge_override_independent() {
    let mut s = Settings::default();
    s.challenge = Challenge::Math;
    s.wrappers.challenge = InheritOr::Set(Challenge::Yes);

    let shell = s.resolved_for(Mode::Shell);
    let wrap = s.resolved_for(Mode::Wrap);

    assert_eq!(shell.challenge, Challenge::Math);
    assert_eq!(wrap.challenge, Challenge::Yes);
}

#[test]
fn wrap_min_severity_override() {
    let mut s = Settings::default();
    s.min_severity = Some(Severity::Medium);
    s.wrappers.min_severity = InheritOr::Set(Some(Severity::Critical));
    let r = s.resolved_for(Mode::Wrap);
    assert_eq!(r.min_severity, Some(Severity::Critical));
}
