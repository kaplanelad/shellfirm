//! CRUD over `~/.shellfirm/checks/*.yaml` files. One file per `from` group.

use crate::checks::Check;
use crate::error::{Error, Result};
use std::path::{Path, PathBuf};

#[derive(Debug)]
pub struct CustomCheckStore {
    root: PathBuf,
}

impl CustomCheckStore {
    #[must_use]
    pub fn new(root: PathBuf) -> Self {
        Self { root }
    }

    #[must_use]
    pub fn root(&self) -> &Path {
        &self.root
    }

    /// Load all custom checks from `root`. Returns empty if dir is missing.
    ///
    /// # Errors
    /// Returns an error if a YAML file cannot be read or parsed.
    pub fn list(&self) -> Result<Vec<Check>> {
        if !self.root.is_dir() {
            return Ok(vec![]);
        }
        crate::checks::load_custom_checks(&self.root)
    }

    /// Path to the YAML file for a given group name.
    #[must_use]
    pub fn path_for_group(&self, group: &str) -> PathBuf {
        self.root.join(format!("{group}.yaml"))
    }

    fn read_group_file(&self, group: &str) -> Result<Vec<Check>> {
        let p = self.path_for_group(group);
        if !p.exists() {
            return Ok(vec![]);
        }
        let content = std::fs::read_to_string(&p)?;
        let checks: Vec<Check> = serde_yaml::from_str(&content)?;
        Ok(checks)
    }

    fn write_group_file(&self, group: &str, checks: &[Check]) -> Result<()> {
        let p = self.path_for_group(group);
        if checks.is_empty() {
            if p.exists() {
                std::fs::remove_file(&p)?;
            }
            return Ok(());
        }
        std::fs::create_dir_all(&self.root)?;
        let content = serde_yaml::to_string(checks)?;
        std::fs::write(&p, content)?;
        Ok(())
    }

    /// Append a new check to its group file.
    ///
    /// # Errors
    /// Returns an error if a check with the same `id` already exists in the
    /// group, or if the underlying file I/O fails.
    pub fn add(&self, c: &Check) -> Result<()> {
        let mut existing = self.read_group_file(&c.from)?;
        if existing.iter().any(|x| x.id == c.id) {
            return Err(Error::Config(format!(
                "check id {:?} already exists in group {:?}",
                c.id, c.from
            )));
        }
        existing.push(c.clone());
        self.write_group_file(&c.from, &existing)
    }

    /// Update an existing check identified by `id`. `previous_group` is needed
    /// because the user may have changed `from`, in which case we move the
    /// check to a different file.
    ///
    /// # Errors
    /// Returns an error if no check with `id` is found in the target group, or
    /// if the underlying file I/O fails.
    pub fn update(&self, c: &Check, previous_group: &str) -> Result<()> {
        if previous_group != c.from {
            // Remove from old file
            let mut old = self.read_group_file(previous_group)?;
            old.retain(|x| x.id != c.id);
            self.write_group_file(previous_group, &old)?;
            // Add to new file
            return self.add(c);
        }
        let mut existing = self.read_group_file(&c.from)?;
        let mut found = false;
        for x in existing.iter_mut() {
            if x.id == c.id {
                *x = c.clone();
                found = true;
                break;
            }
        }
        if !found {
            return Err(Error::Config(format!("check id {:?} not found", c.id)));
        }
        self.write_group_file(&c.from, &existing)
    }

    /// Delete a check by id from its group file. Removes file if it becomes empty.
    ///
    /// # Errors
    /// Returns an error if no check with `id` is found in the group, or if
    /// the underlying file I/O fails.
    pub fn delete(&self, id: &str, group: &str) -> Result<()> {
        let mut existing = self.read_group_file(group)?;
        let before = existing.len();
        existing.retain(|x| x.id != id);
        if existing.len() == before {
            return Err(Error::Config(format!(
                "check id {id:?} not found in group {group:?}"
            )));
        }
        self.write_group_file(group, &existing)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::checks::{Check, Severity};
    use crate::config::Challenge;
    use regex::Regex;

    fn make_check(id: &str, from: &str) -> Check {
        Check {
            id: id.into(),
            test: Regex::new("foo").unwrap(),
            description: "x".into(),
            from: from.into(),
            challenge: Challenge::Math,
            filters: vec![],
            alternative: None,
            alternative_info: None,
            severity: Severity::Medium,
        }
    }

    fn tempfile_dir() -> PathBuf {
        let mut p = std::env::temp_dir();
        p.push(format!("shellfirm-test-{}", uuid::Uuid::new_v4()));
        std::fs::create_dir_all(&p).unwrap();
        p
    }

    #[test]
    fn list_empty_dir() {
        let tmp = tempfile_dir();
        let store = CustomCheckStore::new(tmp);
        assert!(store.list().unwrap().is_empty());
    }

    #[test]
    fn write_then_list() {
        let tmp = tempfile_dir();
        let store = CustomCheckStore::new(tmp);
        let c = make_check("my:foo", "my");
        store.write_group_file("my", &[c.clone()]).unwrap();
        let listed = store.list().unwrap();
        assert_eq!(listed.len(), 1);
        assert_eq!(listed[0].id, "my:foo");
    }

    #[test]
    fn write_empty_removes_file() {
        let tmp = tempfile_dir();
        let store = CustomCheckStore::new(tmp);
        let c = make_check("my:foo", "my");
        store.write_group_file("my", &[c]).unwrap();
        assert!(store.path_for_group("my").exists());
        store.write_group_file("my", &[]).unwrap();
        assert!(!store.path_for_group("my").exists());
    }

    #[test]
    fn add_creates_group_file() {
        let tmp = tempfile_dir();
        let store = CustomCheckStore::new(tmp);
        let c = make_check("my:foo", "my");
        store.add(&c).unwrap();
        let listed = store.list().unwrap();
        assert!(listed.iter().any(|x| x.id == "my:foo"));
    }

    #[test]
    fn add_appends_to_existing_group_file() {
        let tmp = tempfile_dir();
        let store = CustomCheckStore::new(tmp);
        store.add(&make_check("my:a", "my")).unwrap();
        store.add(&make_check("my:b", "my")).unwrap();
        let listed = store.list().unwrap();
        assert_eq!(listed.len(), 2);
    }

    #[test]
    fn add_rejects_duplicate_id() {
        let tmp = tempfile_dir();
        let store = CustomCheckStore::new(tmp);
        store.add(&make_check("my:dup", "my")).unwrap();
        let err = store.add(&make_check("my:dup", "my")).unwrap_err();
        assert!(format!("{err:?}").contains("already exists"));
    }

    #[test]
    fn update_in_place() {
        let tmp = tempfile_dir();
        let store = CustomCheckStore::new(tmp);
        let mut c = make_check("my:foo", "my");
        store.add(&c).unwrap();
        c.description = "updated".into();
        store.update(&c, "my").unwrap();
        let listed = store.list().unwrap();
        assert_eq!(listed[0].description, "updated");
    }

    #[test]
    fn update_moves_between_groups() {
        let tmp = tempfile_dir();
        let store = CustomCheckStore::new(tmp);
        let c = make_check("my:foo", "my");
        store.add(&c).unwrap();
        let mut moved = c.clone();
        moved.from = "team".into();
        store.update(&moved, "my").unwrap();
        assert!(!store.path_for_group("my").exists());
        assert!(store.path_for_group("team").exists());
    }

    #[test]
    fn update_returns_error_when_id_missing() {
        let tmp = tempfile_dir();
        let store = CustomCheckStore::new(tmp);
        let err = store.update(&make_check("my:nope", "my"), "my").unwrap_err();
        assert!(format!("{err:?}").contains("not found"));
    }

    #[test]
    fn delete_removes_check_and_empties_file() {
        let tmp = tempfile_dir();
        let store = CustomCheckStore::new(tmp);
        store.add(&make_check("my:foo", "my")).unwrap();
        store.delete("my:foo", "my").unwrap();
        assert!(!store.path_for_group("my").exists());
    }

    #[test]
    fn delete_one_of_many_keeps_file() {
        let tmp = tempfile_dir();
        let store = CustomCheckStore::new(tmp);
        store.add(&make_check("my:a", "my")).unwrap();
        store.add(&make_check("my:b", "my")).unwrap();
        store.delete("my:a", "my").unwrap();
        let listed = store.list().unwrap();
        assert_eq!(listed.len(), 1);
        assert_eq!(listed[0].id, "my:b");
    }

    #[test]
    fn delete_returns_error_when_id_missing() {
        let tmp = tempfile_dir();
        let store = CustomCheckStore::new(tmp);
        let err = store.delete("my:nope", "my").unwrap_err();
        assert!(format!("{err:?}").contains("not found"));
    }
}
