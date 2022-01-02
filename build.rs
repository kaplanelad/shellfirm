use anyhow::Result;
use std::fs;
use std::fs::File;
use std::io::prelude::*;
use std::path::Path;

fn main() -> Result<()> {
    let destination_file = "./src/checks.yaml";
    if Path::new(&destination_file).exists() {
        fs::remove_file(&destination_file)?;
    }

    let paths = fs::read_dir("./checks")?;
    let mut all_group_checks = String::new();
    for path in paths {
        let contents = fs::read_to_string(format!("{}", path?.path().display()))?;
        all_group_checks.push_str(&contents);
        all_group_checks.push('\n');
    }

    let mut file = File::create(destination_file)?;
    file.write_all(all_group_checks.as_bytes())?;

    Ok(())
}
