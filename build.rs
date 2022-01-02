use anyhow::Result;
use std::env;
use std::fs;
use std::fs::File;
use std::io::prelude::*;
use std::path::Path;

fn main() -> Result<()> {
    println!("cargo:rerun-if-changed=checks/");

    let out_dir = env::var("OUT_DIR")?;
    let dest_checks_path = Path::new(&out_dir).join("all-checks.yaml");

    let paths = fs::read_dir("./checks")?;
    let mut all_group_checks = String::new();
    for path in paths {
        let contents = fs::read_to_string(format!("{}", path?.path().display()))?;
        all_group_checks.push_str(&contents);
        all_group_checks.push('\n');
    }

    let mut file = File::create(dest_checks_path)?;
    file.write_all(all_group_checks.as_bytes())?;

    Ok(())
}
