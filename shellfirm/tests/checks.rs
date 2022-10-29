use std::{fs, path::PathBuf};

use insta::assert_debug_snapshot;
use itertools::Itertools;
use serde_derive::Deserialize;
use shellfirm::checks::run_check_on_command;

#[derive(Debug, Deserialize, Clone)]
struct TestSensitivePatterns {
    pub test: String,
    pub description: String,
}

#[derive(Debug, Deserialize, Clone)]
struct TestSensitivePatternsResult {
    pub file_path: String,
    pub test: String,
    pub check_detection_ids: Vec<String>,
    pub test_description: String,
}

#[test]
fn test_checks() {
    let checks = shellfirm::checks::get_all().unwrap();

    let test_files_path = fs::read_dir("./tests/checks")
        .unwrap()
        .filter_map(|entry| entry.ok().map(|e| e.path()))
        .collect::<Vec<PathBuf>>();

    for file in test_files_path {
        let file_name = file.file_name().unwrap().to_str().unwrap().to_string();
        let mut test_file_results: Vec<TestSensitivePatternsResult> = Vec::new();
        let tests: Vec<TestSensitivePatterns> =
            serde_yaml::from_reader(std::fs::File::open(&file.display().to_string()).unwrap())
                .unwrap();

        for test in tests {
            let run_result = run_check_on_command(&checks, &test.test);

            test_file_results.push(TestSensitivePatternsResult {
                file_path: file_name.clone(),
                test: test.test,
                check_detection_ids: run_result
                    .iter()
                    .map(|f| f.id.to_string())
                    .sorted_by(|a, b| Ord::cmp(&b, &a))
                    .collect::<Vec<_>>(),
                test_description: test.description,
            });
        }
        assert_debug_snapshot!(file_name, test_file_results);
    }
}

#[test]
fn test_missing_patterns_coverage() {
    let checks = shellfirm::checks::get_all().unwrap();

    let test_files_path = fs::read_dir("./tests/checks")
        .unwrap()
        .filter_map(|entry| {
            entry
                .ok()
                .map(|e| e.file_name().to_str().unwrap().to_string())
        })
        .collect::<Vec<String>>();

    let mut not_covered = vec![];
    for check in checks {
        if !test_files_path.contains(&format!("{}.yaml", &check.id.replace(':', "-"))) {
            not_covered.push(check.id);
        }
    }
    assert_debug_snapshot!(not_covered);
}
