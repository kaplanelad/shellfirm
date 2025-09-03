use serde::{Deserialize, Serialize};
use shellfirm_core::{get_all_checks, ValidationOptions};
use std::collections::HashMap;
use std::fs;
use std::path::Path;

#[derive(Debug, Deserialize, Serialize)]
struct TestCase {
    check_id: String,
    should_catch: Vec<String>,
    should_not_catch: Vec<String>,
}

#[derive(Debug)]
struct TestResult {
    check_id: String,
    passed: bool,
    failures: Vec<String>,
}

struct CheckTestRunner {
    tests_dir: String,
}

impl CheckTestRunner {
    fn new(tests_dir: &str) -> Self {
        Self {
            tests_dir: tests_dir.to_string(),
        }
    }

    fn discover_test_files(&self) -> Result<HashMap<String, String>, Box<dyn std::error::Error>> {
        let mut test_files = HashMap::new();
        let tests_path = Path::new(&self.tests_dir);

        if !tests_path.exists() {
            return Ok(test_files);
        }

        for entry in fs::read_dir(tests_path)? {
            let entry = entry?;
            let path = entry.path();

            if path.is_dir() {
                let category = path
                    .file_name()
                    .and_then(|n| n.to_str())
                    .ok_or("Invalid category name")?;

                for test_entry in fs::read_dir(&path)? {
                    let test_entry = test_entry?;
                    let test_path = test_entry.path();

                    if test_path.is_file()
                        && test_path.extension().map_or(false, |ext| ext == "yaml")
                    {
                        if let Some(file_stem) = test_path.file_stem() {
                            if let Some(name) = file_stem.to_str() {
                                let check_id = format!("{}:{}", category, name);
                                test_files
                                    .insert(check_id, test_path.to_string_lossy().to_string());
                            }
                        }
                    }
                }
            }
        }

        Ok(test_files)
    }

    fn run_test_case(
        &self,
        test_case: &TestCase,
    ) -> Result<TestResult, Box<dyn std::error::Error>> {
        let mut result = TestResult {
            check_id: test_case.check_id.clone(),
            passed: true,
            failures: Vec::new(),
        };

        // Test should_catch commands
        for command in &test_case.should_catch {
            let validation_result = shellfirm_core::checks::validate_command(command);

            if !validation_result.should_challenge {
                result.passed = false;
                result.failures.push(format!(
                    "should_catch\n  command: {}\n  expected: ONLY '{}' should match\n  actual: no match (should_challenge=false)",
                    command, test_case.check_id
                ));
                continue;
            }

            let matched_ids: Vec<String> = validation_result
                .matches
                .iter()
                .map(|c| c.id.clone())
                .collect();

            // Enforce uniqueness: exactly 1 match and it is the expected check_id
            if matched_ids.len() != 1 || matched_ids[0] != test_case.check_id {
                result.passed = false;
                result.failures.push(format!(
                    "should_catch\n  command: {}\n  expected: ONLY '{}' should match\n  actual: matched ids: {:?}",
                    command, test_case.check_id, matched_ids
                ));
            }
        }

        // Auto-combined test: first should_not_catch && first should_catch should match via validate_command_with_split
        if let (Some(nc), Some(c)) = (
            test_case.should_not_catch.first(),
            test_case.should_catch.first(),
        ) {
            let checks = get_all_checks()?;
            let options = ValidationOptions::default();
            let combo = format!("{nc} && {c}");
            let matches =
                shellfirm_core::checks::validate_command_with_split(&checks, &combo, &options);
            let matched_ids: Vec<String> = matches.iter().map(|x| x.id.clone()).collect();
            // Allow multiple matches here; ensure expected check_id is present
            if !matched_ids.iter().any(|id| id == &test_case.check_id) {
                result.passed = false;
                result.failures.push(format!(
                    "auto_combine_should_catch\n  command: {}\n  expected: '{}' to be among matches\n  actual: matched ids: {:?}",
                    combo, test_case.check_id, matched_ids
                ));
            }
        }

        // Test should_not_catch commands
        for command in &test_case.should_not_catch {
            let validation_result = shellfirm_core::checks::validate_command(command);

            // Only fail if THIS specific check matched; allow overlaps from other checks
            let matched_this_check = validation_result
                .matches
                .iter()
                .any(|c| c.id == test_case.check_id);

            if matched_this_check {
                result.passed = false;
                let matched_ids: Vec<String> = validation_result
                    .matches
                    .iter()
                    .map(|c| c.id.clone())
                    .collect();
                result.failures.push(format!(
                    "should_not_catch\n  command: {}\n  expected: no match for '{}'\n  actual: matched ids: {:?}",
                    command, test_case.check_id, matched_ids
                ));
            }
        }

        Ok(result)
    }
}

// Removed specific per-check test; use dynamic test below

#[test]
fn test_run_all_yaml_tests() {
    // Fail fast if embedded checks cannot be parsed (e.g., invalid regex)
    get_all_checks().expect("Failed to load embedded checks (invalid regex or YAML)");

    // Point to the new tests directory outside of checks to avoid interfering with build.rs
    let runner = CheckTestRunner::new("../checks-tests");

    // Discover files and run each file independently (in parallel) for clearer output
    let test_files = runner
        .discover_test_files()
        .expect("Failed to discover test files");

    // Optional filter to run a single YAML test file by name/path.
    // Usage: SHELLFIRM_YAML_TEST_FILTER="fs::delete_find_files" cargo test test_run_all_yaml_tests -- --nocapture
    let name_filter = std::env::var("SHELLFIRM_YAML_TEST_FILTER").ok();

    use std::sync::{Arc, Mutex};
    let failures: Arc<Mutex<Vec<String>>> = Arc::new(Mutex::new(Vec::new()));

    let mut handles = Vec::new();
    for (check_hint, path) in test_files {
        let runner = CheckTestRunner::new(&runner.tests_dir);
        let failures = Arc::clone(&failures);
        let path_clone = path.clone();
        // Derive a readable name, e.g., base::bash_fork_bomb
        let name = if let Some((dir, file)) = Path::new(&path)
            .parent()
            .and_then(|p| p.file_name())
            .and_then(|d| d.to_str())
            .zip(Path::new(&path).file_stem().and_then(|f| f.to_str()))
        {
            format!("{dir}::{file}")
        } else {
            check_hint.clone()
        };

        // Apply filter if provided
        if let Some(ref f) = name_filter {
            if !name.contains(f) && !path.contains(f) && !check_hint.contains(f) {
                continue;
            }
        }

        handles.push(std::thread::spawn(move || {
            // Multi-doc support per file
            let content = fs::read_to_string(&path_clone)
                .unwrap_or_else(|e| panic!("Failed to read {path_clone}: {e}"));
            let docs = serde_yaml::Deserializer::from_str(&content);

            let mut file_failures: Vec<String> = Vec::new();
            for doc in docs {
                let test_case: TestCase = TestCase::deserialize(doc)
                    .unwrap_or_else(|e| panic!("Failed to parse {path_clone}: {e}"));
                let result = runner
                    .run_test_case(&test_case)
                    .unwrap_or_else(|e| panic!("Failed to run {}: {}", test_case.check_id, e));
                if !result.passed {
                    let block = format!("{}\n{}", result.check_id, result.failures.join("\n"));
                    file_failures.push(block);
                }
            }

            if file_failures.is_empty() {
                println!("test {name} ... ok");
            } else {
                println!("test {name} ... FAILED");
                let mut guard = failures.lock().expect("Failed to acquire lock on failures");
                guard.extend(file_failures);
            }
        }));
    }

    for h in handles {
        let _ = h.join();
    }

    let failures = Arc::try_unwrap(failures)
        .expect("Failed to unwrap Arc")
        .into_inner()
        .expect("Failed to unwrap Mutex");
    assert!(
        failures.is_empty(),
        "Some YAML tests failed:\n{}",
        failures.join("\n")
    );
}
