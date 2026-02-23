use std::{collections::HashSet, fs, path::PathBuf};

use serde_derive::Deserialize;
use shellfirm::checks::run_check_on_command_with_env;

/// A single test case in the consolidated YAML files.
#[derive(Debug, Deserialize, Clone)]
struct CheckTest {
    /// The command string to test against all check patterns.
    pub test: String,
    /// Human-readable description of what this test verifies.
    pub description: String,
    /// Exact set of check IDs that should match.
    /// Empty `[]` means the command must NOT match anything.
    pub expect_ids: Vec<String>,
}

/// A mock environment where every path is reported as existing.
/// This ensures check tests focus on regex matching, not filesystem state.
struct AllPathsExistEnv;

impl shellfirm::env::Environment for AllPathsExistEnv {
    fn var(&self, _key: &str) -> Option<String> {
        None
    }
    fn current_dir(&self) -> shellfirm::error::Result<PathBuf> {
        Ok(PathBuf::from("/mock"))
    }
    fn path_exists(&self, _path: &std::path::Path) -> bool {
        true
    }
    fn home_dir(&self) -> Option<PathBuf> {
        Some(PathBuf::from("/home/user"))
    }
    fn run_command(&self, _cmd: &str, _args: &[&str], _timeout_ms: u64) -> Option<String> {
        None
    }
    fn read_file(&self, _path: &std::path::Path) -> shellfirm::error::Result<String> {
        Err(shellfirm::error::Error::Other("not implemented".into()))
    }
    fn find_file_upward(&self, _start: &std::path::Path, _filename: &str) -> Option<PathBuf> {
        None
    }
}

/// Run every test case from every consolidated YAML file in `tests/checks/`
/// and assert that the matched check IDs exactly equal `expect_ids`.
///
/// Uses a mock environment where all paths exist so that `PathExists` filters
/// always pass. This isolates regex-matching tests from filesystem state.
#[test]
fn test_all_checks() {
    let checks = shellfirm::checks::get_all().unwrap();
    let env = AllPathsExistEnv;

    let test_files: Vec<PathBuf> = fs::read_dir("./tests/checks")
        .unwrap()
        .filter_map(|entry| entry.ok().map(|e| e.path()))
        .filter(|p| p.extension().map_or(false, |ext| ext == "yaml"))
        .collect();

    assert!(
        !test_files.is_empty(),
        "No test YAML files found in tests/checks/"
    );

    let mut total_cases = 0;
    let mut total_positive = 0;
    let mut total_negative = 0;

    for file in &test_files {
        let content = fs::read_to_string(file).unwrap();
        let cases: Vec<CheckTest> = serde_yaml::from_str(&content).unwrap_or_else(|e| {
            panic!("Failed to parse {}: {}", file.display(), e);
        });

        for case in &cases {
            let matched = run_check_on_command_with_env(&checks, &case.test, &env);
            let mut got_ids: Vec<String> = matched.iter().map(|c| c.id.clone()).collect();
            got_ids.sort();

            let mut want_ids = case.expect_ids.clone();
            want_ids.sort();

            assert_eq!(
                got_ids,
                want_ids,
                "\n  File: {}\n  Command: {:?}\n  Description: {}\n  Expected: {:?}\n  Got: {:?}\n",
                file.display(),
                case.test,
                case.description,
                want_ids,
                got_ids,
            );

            total_cases += 1;
            if case.expect_ids.is_empty() {
                total_negative += 1;
            } else {
                total_positive += 1;
            }
        }
    }

    eprintln!(
        "  check tests: {} total ({} positive, {} negative) across {} files",
        total_cases,
        total_positive,
        total_negative,
        test_files.len()
    );
}

/// Verify that every check ID returned by `get_all()` appears in at least
/// one `expect_ids` list across all test files. This ensures 100% coverage.
#[test]
fn test_coverage_completeness() {
    let checks = shellfirm::checks::get_all().unwrap();

    let all_check_ids: HashSet<String> = checks.iter().map(|c| c.id.clone()).collect();

    let mut covered_ids: HashSet<String> = HashSet::new();

    let test_files: Vec<PathBuf> = fs::read_dir("./tests/checks")
        .unwrap()
        .filter_map(|entry| entry.ok().map(|e| e.path()))
        .filter(|p| p.extension().map_or(false, |ext| ext == "yaml"))
        .collect();

    for file in &test_files {
        let content = fs::read_to_string(file).unwrap();
        let cases: Vec<CheckTest> = serde_yaml::from_str(&content).unwrap_or_else(|e| {
            panic!("Failed to parse {}: {}", file.display(), e);
        });

        for case in cases {
            for id in &case.expect_ids {
                covered_ids.insert(id.clone());
            }
        }
    }

    let mut missing: Vec<&String> = all_check_ids.difference(&covered_ids).collect();
    missing.sort();

    assert!(
        missing.is_empty(),
        "Check IDs without any positive test case:\n  {}\n\nAdd test cases with these IDs in expect_ids to the appropriate test file in tests/checks/",
        missing
            .iter()
            .map(|id| id.as_str())
            .collect::<Vec<_>>()
            .join("\n  ")
    );
}
