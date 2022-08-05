#![allow(dead_code)]
use anyhow::Result as AnyResult;
use clap::{AppSettings, Arg, Command};
use duct::cmd;
use fs_extra as fsx;
use fsx::dir::CopyOptions;
use glob::glob;
use std::{
    fs::create_dir_all,
    path::{Path, PathBuf},
};

const TEMPLATE_PROJECT_NAME: &str = "shellfirm";
fn main() -> Result<(), anyhow::Error> {
    let cli = Command::new("xtask")
        .setting(AppSettings::SubcommandRequiredElseHelp)
        .subcommand(
            Command::new("coverage").arg(
                Arg::new("dev")
                    .short('d')
                    .long("dev")
                    .help("generate an html report")
                    .takes_value(false),
            ),
        )
        .subcommand(Command::new("ci"))
        .subcommand(Command::new("vars"));

    let matches = cli.get_matches();

    let root = root_dir();
    let project = root.join(TEMPLATE_PROJECT_NAME);
    let res = match matches.subcommand() {
        Some(("coverage", sm)) => {
            remove_dir("coverage")?;
            create_dir_all("coverage")?;

            println!("=== running coverage ===");
            cmd!("cargo", "test")
                .env("CARGO_INCREMENTAL", "0")
                .env("RUSTFLAGS", "-Cinstrument-coverage")
                .env("LLVM_PROFILE_FILE", "cargo-test-%p-%m.profraw")
                .run()?;
            println!("ok.");

            println!("=== generating report ===");
            let devmode = sm.is_present("dev");
            let (fmt, file) = if devmode {
                ("html", "coverage/html")
            } else {
                ("lcov", "coverage/tests.lcov")
            };
            cmd!(
                "grcov",
                ".",
                "--binary-path",
                "./target/debug/deps",
                "-s",
                ".",
                "-t",
                fmt,
                "--branch",
                "--ignore-not-existing",
                "--ignore",
                "../*",
                "--ignore",
                "/*",
                "--ignore",
                "xtask/*",
                "--ignore",
                "*/src/tests/*",
                "-o",
                file,
            )
            .run()?;
            println!("ok.");

            println!("=== cleaning up ===");
            clean_files("**/*.profraw")?;
            println!("ok.");
            if devmode {
                if confirm("open report folder?") {
                    cmd!("open", file).run()?;
                } else {
                    println!("report location: {}", file);
                }
            }

            Ok(())
        }
        Some(("vars", _)) => {
            println!("project root: {:?}", project);
            println!("root: {:?}", root);
            Ok(())
        }
        Some(("ci", _)) => {
            cmd!("cargo", "+nightly", "fmt", "--all", "--", "--check").run()?;
            cmd!("cargo", "clippy", "--", "-D", "warnings").run()?;
            cmd!("cargo", "test").run()?;
            Ok(())
        }
        _ => unreachable!("unreachable branch"),
    };
    res
}

fn clean_files(pattern: &str) -> AnyResult<()> {
    let files: Result<Vec<PathBuf>, _> = glob(pattern)?.collect();
    files?.iter().try_for_each(remove_file)
}

fn remove_file<P>(path: P) -> AnyResult<()>
where
    P: AsRef<Path>,
{
    fsx::file::remove(path).map_err(anyhow::Error::msg)
}

fn remove_dir<P>(path: P) -> AnyResult<()>
where
    P: AsRef<Path>,
{
    fsx::dir::remove(path).map_err(anyhow::Error::msg)
}

fn exists<P>(path: P) -> bool
where
    P: AsRef<Path>,
{
    std::path::Path::exists(path.as_ref())
}

fn copy_contents<P, Q>(from: P, to: Q, overwrite: bool) -> AnyResult<u64>
where
    P: AsRef<Path>,
    Q: AsRef<Path>,
{
    let mut opts = CopyOptions::new();
    opts.content_only = true;
    opts.overwrite = overwrite;
    fsx::dir::copy(from, to, &opts).map_err(anyhow::Error::msg)
}

fn confirm(question: &str) -> bool {
    let question = requestty::Question::confirm("anonymous")
        .message(question)
        .build();

    requestty::prompt_one(question).unwrap().as_bool().unwrap()
}
fn root_dir() -> PathBuf {
    let mut xtask_dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    xtask_dir.pop();
    xtask_dir
}
