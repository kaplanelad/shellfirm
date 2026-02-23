use std::{env, fs, fs::File, io::prelude::*, path::Path};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    println!("cargo:rerun-if-changed=checks/");

    let out_dir = env::var("OUT_DIR")?;

    let dest_checks_path = Path::new(&out_dir).join("all-checks.yaml");
    let dest_groups = Path::new(&out_dir).join("all_the_files.rs");
    let mut groups_names = File::create(dest_groups)?;

    writeln!(&mut groups_names, r"[",)?;

    let mut paths: Vec<_> = fs::read_dir("./checks")?.filter_map(Result::ok).collect();
    paths.sort_by_key(std::fs::DirEntry::path);

    let mut all_group_checks = String::new();
    for entry in &paths {
        let path_name = format!("{}", entry.path().display());
        let contents = fs::read_to_string(&path_name)?;
        all_group_checks.push_str(&contents);
        all_group_checks.push('\n');

        let file_name = Path::new(&path_name)
            .file_stem()
            .unwrap()
            .to_str()
            .expect("could not get file name");
        writeln!(&mut groups_names, r#""{file_name}","#)?;
    }

    writeln!(&mut groups_names, r"]",)?;

    let mut file = File::create(dest_checks_path)?;
    file.write_all(all_group_checks.as_bytes())?;

    Ok(())
}
