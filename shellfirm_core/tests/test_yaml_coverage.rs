use shellfirm_core::get_all_checks;
use std::path::Path;

#[test]
fn test_every_check_has_yaml_test() {
    // Ensure checks are loadable
    let checks = get_all_checks().expect("Failed to load embedded checks (invalid regex or YAML)");

    let tests_root = Path::new("../checks-tests");

    let mut missing: Vec<String> = Vec::new();
    for check in checks {
        if let Some((category, name)) = check.id.split_once(':') {
            let expected = tests_root.join(category).join(format!("{name}.yaml"));
            if !expected.exists() {
                missing.push(format!("{} -> {}", check.id, expected.display()));
            }
        } else {
            missing.push(format!("invalid id format: {}", check.id));
        }
    }

    assert!(
        missing.is_empty(),
        "Missing YAML tests for some checks (category/name.yaml):\n{}",
        missing.join("\n")
    );
}
