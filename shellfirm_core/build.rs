use std::{env, fs, fs::File, io::prelude::*, path::Path};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    println!("cargo:rerun-if-changed=../checks/");

    let out_dir = env::var("OUT_DIR")?;
    let dest_checks_path = Path::new(&out_dir).join("all-checks.yaml");

    // Try multiple possible paths for checks directory
    let possible_paths = ["../checks", "../../checks", "../../../checks", "checks"];

    let mut checks_path = None;
    for path in &possible_paths {
        if Path::new(path).exists() {
            checks_path = Some(*path);
            break;
        }
    }

    let checks_path = checks_path.ok_or_else(|| {
        let msg = format!("Checks directory not found. Tried paths: {possible_paths:?}");
        std::io::Error::new(std::io::ErrorKind::NotFound, msg)
    })?;

    println!("cargo:warning=Using checks directory: {checks_path}");

    let paths = fs::read_dir(checks_path)?;

    let mut all_group_checks = String::new();
    for path in paths {
        let path_name = format!("{}", &path?.path().display());
        let contents = fs::read_to_string(&path_name)?;
        all_group_checks.push_str(&contents);
        all_group_checks.push('\n');
    }

    let mut file = File::create(dest_checks_path)?;
    file.write_all(all_group_checks.as_bytes())?;

    Ok(())
}
