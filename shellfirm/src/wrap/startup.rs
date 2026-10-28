//! What a wrapped client runs from its own command line.
//!
//! `shellfirm wrap psql -c 'DROP TABLE users'` (or an alias
//! `psql='shellfirm wrap psql'`) runs SQL before the interactive session
//! starts: `psql -c` / `-f`, `mysql -e` / `--init-command`, `mongosh --eval`
//! / script files, `sqlite3 db "SQL"`, `redis-cli FLUSHALL`, ... This module
//! turns the client's argv into the [`Submission`] the session would check
//! had the same text been typed, so the wrap checks it before it spawns the
//! client (with or without a shell hook in front of it).

use super::{
    lexer::{normalize_ws, Dialect, MetaCommand, MetaKind},
    line::{ScriptReader, Submission},
};

/// Something a client runs from its command line.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Payload {
    /// SQL / JavaScript / a command line, as typed in the session.
    Script(String),
    /// A file of SQL / JavaScript (`psql -f`, `mongosh script.js`).
    File { raw: String, path: String },
    /// A shell command (`psql -o '|cmd'`).
    Shell { raw: String, command: String },
}

/// How a client's options are written.
struct OptSpec {
    /// Short options that take a value (`-c SQL`, `-cSQL`).
    short_arg: &'static str,
    /// Short options whose value is only ever attached (mysql `-pSECRET`).
    short_attached: &'static str,
    /// Long options (without dashes) that take a value (`--file F`,
    /// `--file=F`).
    long_arg: &'static [&'static str],
    /// Long options are written with one dash (`sqlite3 -cmd X`).
    single_dash_long: bool,
    /// Options whose value is a payload: always take the next word, even
    /// when it starts with `-`.
    payload: &'static [&'static str],
}

/// One parsed option: its name (`-c`, `--command`, `-cmd`) and value.
#[derive(Debug)]
struct Opt {
    name: String,
    value: Option<String>,
}

/// Parse `args` with `spec`: options in order, and the positional words.
fn parse(args: &[String], spec: &OptSpec) -> (Vec<Opt>, Vec<String>) {
    let mut opts = Vec::new();
    let mut positional = Vec::new();
    let mut i = 0;
    // The next word as the value of `name`, unless it looks like another
    // option (an option with an optional value, e.g. mongosh `-p`).
    let take_next = |i: &mut usize, name: &str| -> Option<String> {
        let next = args.get(*i + 1)?;
        if next.len() > 1 && next.starts_with('-') && !spec.payload.contains(&name) {
            return None;
        }
        *i += 1;
        Some(next.clone())
    };
    while i < args.len() {
        let a = args[i].as_str();
        if a == "--" {
            positional.extend(args[i + 1..].iter().cloned());
            break;
        }
        let long = a
            .strip_prefix("--")
            .or_else(|| a.strip_prefix('-').filter(|_| spec.single_dash_long));
        if let Some(body) = long.filter(|b| !b.is_empty()) {
            if let Some((name, value)) = body.split_once('=') {
                opts.push(Opt {
                    name: name.to_string(),
                    value: Some(value.to_string()),
                });
                i += 1;
                continue;
            }
            if spec.long_arg.contains(&body) {
                let value = take_next(&mut i, body);
                opts.push(Opt {
                    name: body.to_string(),
                    value,
                });
                i += 1;
                continue;
            }
            if spec.single_dash_long && !a.starts_with("--") && body.chars().count() > 1 {
                // An unknown `-word` of a single-dash client: a flag.
                opts.push(Opt {
                    name: body.to_string(),
                    value: None,
                });
                i += 1;
                continue;
            }
            if a.starts_with("--") {
                opts.push(Opt {
                    name: body.to_string(),
                    value: None,
                });
                i += 1;
                continue;
            }
        }
        if a.len() > 1 && a.starts_with('-') {
            // Short cluster: `-Atc SQL`, `-cSQL`, `-uroot`.
            let flags: Vec<char> = a[1..].chars().collect();
            for (j, f) in flags.iter().enumerate() {
                let attached: String = flags[j + 1..].iter().collect();
                let name = f.to_string();
                if spec.short_attached.contains(*f) {
                    opts.push(Opt {
                        name,
                        value: Some(attached).filter(|v| !v.is_empty()),
                    });
                    break;
                }
                if spec.short_arg.contains(*f) {
                    let value = if attached.is_empty() {
                        take_next(&mut i, &name)
                    } else {
                        Some(attached)
                    };
                    opts.push(Opt { name, value });
                    break;
                }
                opts.push(Opt { name, value: None });
            }
            i += 1;
            continue;
        }
        positional.push(a.to_string());
        i += 1;
    }
    (opts, positional)
}

const PSQL: OptSpec = OptSpec {
    short_arg: "cdfhLopTUvPFR",
    short_attached: "",
    long_arg: &[
        "command",
        "dbname",
        "file",
        "host",
        "log-file",
        "output",
        "port",
        "table-attr",
        "username",
        "variable",
        "set",
        "pset",
        "field-separator",
        "record-separator",
    ],
    single_dash_long: false,
    payload: &["c", "command"],
};

const MYSQL: OptSpec = OptSpec {
    short_arg: "DehPSu",
    short_attached: "p",
    long_arg: &[
        "execute",
        "init-command",
        "database",
        "host",
        "port",
        "socket",
        "user",
        "default-character-set",
        "defaults-file",
        "defaults-extra-file",
        "login-path",
    ],
    single_dash_long: false,
    payload: &["e", "execute", "init-command"],
};

const MONGOSH: OptSpec = OptSpec {
    short_arg: "upf",
    short_attached: "",
    long_arg: &[
        "eval",
        "file",
        "host",
        "port",
        "username",
        "password",
        "authenticationDatabase",
        "authenticationMechanism",
        "apiVersion",
        "tlsCAFile",
        "tlsCertificateKeyFile",
        "tlsCertificateKeyFilePassword",
        "tlsCRLFile",
        "tlsCertificateSelector",
        "tlsDisabledProtocols",
        "awsAccessKeyId",
        "awsSecretAccessKey",
        "awsSessionToken",
        "gssapiServiceName",
        "sspiHostnameCanonicalization",
        "sspiRealmOverride",
        "keyVaultNamespace",
        "kmsURL",
        "csfleLibraryPath",
        "cryptSharedLibPath",
        "oidcFlows",
        "oidcRedirectUri",
        "browser",
    ],
    single_dash_long: false,
    payload: &["eval"],
};

const SQLITE: OptSpec = OptSpec {
    short_arg: "csf",
    short_attached: "",
    long_arg: &[
        "cmd",
        "init",
        "separator",
        "newline",
        "nullvalue",
        "vfs",
        "maxsize",
        "mmap",
        "heap",
        "escape",
        "A",
    ],
    single_dash_long: true,
    payload: &["cmd", "c", "s"],
};

const REDIS: OptSpec = OptSpec {
    short_arg: "hpsauinrdD",
    short_attached: "",
    long_arg: &[
        "user",
        "pass",
        "cacert",
        "cacertdir",
        "cert",
        "key",
        "sni",
        "tls-ciphers",
        "tls-ciphersuites",
        "rdb",
        "functions-rdb",
        "eval",
        "pattern",
        "quoted-pattern",
        "count",
        "memkeys-samples",
        "cluster-only-masters",
    ],
    single_dash_long: false,
    payload: &[],
};

const CLICKHOUSE: OptSpec = OptSpec {
    short_arg: "qhudfm",
    short_attached: "",
    long_arg: &[
        "query",
        "queries-file",
        "host",
        "port",
        "user",
        "password",
        "database",
        "format",
        "config-file",
    ],
    single_dash_long: false,
    payload: &["q", "query"],
};

const CQLSH: OptSpec = OptSpec {
    short_arg: "eufkp",
    short_attached: "",
    long_arg: &[
        "execute",
        "file",
        "username",
        "password",
        "keyspace",
        "cqlversion",
        "encoding",
        "connect-timeout",
        "request-timeout",
    ],
    single_dash_long: false,
    payload: &["e", "execute"],
};

const SQLCMD: OptSpec = OptSpec {
    short_arg: "QqiSdUPHlotsvfcmhawyYr",
    short_attached: "",
    long_arg: &["query", "initial-query", "input-file", "server", "database"],
    single_dash_long: false,
    payload: &["Q", "q", "query", "initial-query"],
};

fn is_opt(o: &Opt, names: &[&str]) -> bool {
    names.contains(&o.name.as_str())
}

fn file_payload(flag: &str, path: &str) -> Option<Payload> {
    (!path.is_empty() && path != "-").then(|| Payload::File {
        raw: format!("{flag} {path}"),
        path: path.to_string(),
    })
}

/// The options of `args` that run a script (`script_opts`) or a file
/// (`file_opts`, a comma-separated list for sqlcmd `-i`), in order, and the
/// positional words.
fn options(
    args: &[String],
    spec: &OptSpec,
    script_opts: &[&str],
    file_opts: &[&str],
) -> (Vec<Payload>, Vec<String>) {
    let (opts, positional) = parse(args, spec);
    let mut out = Vec::new();
    for o in &opts {
        let Some(v) = o.value.as_deref() else {
            continue;
        };
        if is_opt(o, script_opts) {
            out.push(Payload::Script(v.to_string()));
        } else if is_opt(o, file_opts) {
            let dashes = if o.name.chars().count() == 1 || spec.single_dash_long {
                "-"
            } else {
                "--"
            };
            for f in v.split(',') {
                out.extend(file_payload(&format!("{dashes}{}", o.name), f.trim()));
            }
        }
    }
    (out, positional)
}

fn psql_payloads(args: &[String]) -> Vec<Payload> {
    let (opts, _) = parse(args, &PSQL);
    let mut out = Vec::new();
    for o in opts {
        let Some(v) = o.value.as_deref() else {
            continue;
        };
        if is_opt(&o, &["c", "command"]) {
            out.push(Payload::Script(v.to_string()));
        } else if is_opt(&o, &["f", "file"]) {
            out.extend(file_payload("-f", v));
        } else if is_opt(&o, &["o", "output"]) {
            if let Some(cmd) = v.trim_start().strip_prefix('|') {
                out.push(Payload::Shell {
                    raw: format!("-o {v}"),
                    command: cmd.trim().to_string(),
                });
            }
        }
    }
    out
}

fn mysql_payloads(args: &[String]) -> Vec<Payload> {
    let (opts, _) = parse(args, &MYSQL);
    // `--init-command` runs first, then `-e`.
    let init = opts.iter().filter(|o| is_opt(o, &["init-command"]));
    let exec = opts.iter().filter(|o| is_opt(o, &["e", "execute"]));
    init.chain(exec)
        .filter_map(|o| o.value.clone().map(Payload::Script))
        .collect()
}

/// What `tool` runs from `args` (its arguments, after any `sudo`,
/// `docker exec`, ... in front of it), in the order it runs them.
#[must_use]
pub fn payloads(tool: &str, args: &[String]) -> Vec<Payload> {
    match tool {
        "psql" | "pgcli" => psql_payloads(args),
        "mysql" | "mariadb" | "mycli" => mysql_payloads(args),
        "mongosh" | "mongo" => {
            let (mut out, positional) = options(args, &MONGOSH, &["eval"], &["f", "file"]);
            // `mongosh [address] [file.js ...]`: the scripts run in order.
            out.extend(
                positional
                    .iter()
                    .filter(|p| {
                        std::path::Path::new(p)
                            .extension()
                            .is_some_and(|e| e.eq_ignore_ascii_case("js"))
                    })
                    .map(|p| Payload::File {
                        raw: p.clone(),
                        path: p.clone(),
                    }),
            );
            out
        }
        "sqlite3" | "sqlite" | "duckdb" | "litecli" => {
            let (mut out, positional) = options(args, &SQLITE, &["cmd", "c", "s"], &["init", "f"]);
            // `sqlite3 app.db "SQL" ...`: every word after the database runs.
            out.extend(positional.into_iter().skip(1).map(Payload::Script));
            out
        }
        "redis-cli" | "valkey-cli" | "keydb-cli" => {
            let (_, positional) = parse(args, &REDIS);
            if positional.is_empty() {
                Vec::new()
            } else {
                vec![Payload::Script(positional.join(" "))]
            }
        }
        "clickhouse-client" | "clickhouse" => {
            // `clickhouse client -q ...`
            let args = if args.first().is_some_and(|a| a == "client") {
                &args[1..]
            } else {
                args
            };
            options(args, &CLICKHOUSE, &["q", "query"], &["queries-file"]).0
        }
        "cqlsh" => options(args, &CQLSH, &["e", "execute"], &["f", "file"]).0,
        "sqlcmd" => {
            options(
                args,
                &SQLCMD,
                &["Q", "q", "query", "initial-query"],
                &["i", "input-file"],
            )
            .0
        }
        // `sqlplus user/pw@db @script.sql`
        "sqlplus" => args
            .iter()
            .filter_map(|a| a.strip_prefix('@').filter(|p| !p.is_empty()))
            .filter_map(|p| file_payload("@", p))
            .collect(),
        _ => Vec::new(),
    }
}

/// The statements and meta-commands the payloads run, read with the
/// client's lexer (`dialect`; `None` for line-mode clients such as
/// redis-cli, where each line is one command).
#[must_use]
pub fn submission(payloads: &[Payload], dialect: Option<Dialect>) -> Submission {
    let mut sub = Submission::default();
    for p in payloads {
        match p {
            Payload::Script(text) => {
                let Some(d) = dialect else {
                    sub.statements
                        .extend(text.lines().map(normalize_ws).filter(|l| !l.is_empty()));
                    continue;
                };
                let mut reader = ScriptReader::new(d);
                for line in text.lines() {
                    reader.push_line(line, &mut sub);
                    if d == Dialect::JavaScript {
                        // mongosh `--eval` often has no `;`: also check
                        // every line on its own.
                        let l = normalize_ws(line);
                        if !l.is_empty() && !sub.statements.contains(&l) {
                            sub.statements.push(l);
                        }
                    }
                }
                reader.finish(&mut sub);
            }
            Payload::File { raw, path } => sub.metas.push(MetaCommand {
                raw: raw.trim().to_string(),
                kind: MetaKind::RunFile {
                    path: path.clone(),
                    relative: false,
                },
            }),
            Payload::Shell { raw, command } => sub.metas.push(MetaCommand {
                raw: raw.clone(),
                kind: MetaKind::Shell {
                    command: command.clone(),
                },
            }),
        }
    }
    sub
}

#[cfg(test)]
mod tests {
    use super::*;

    fn words(s: &[&str]) -> Vec<String> {
        s.iter().map(|w| (*w).to_string()).collect()
    }

    #[test]
    fn psql_options() {
        let p = payloads(
            "psql",
            &words(&[
                "-h",
                "db",
                "-U",
                "postgres",
                "-Atc",
                "DROP TABLE users",
                "prod",
            ]),
        );
        assert_eq!(p, vec![Payload::Script("DROP TABLE users".into())]);
        let p = payloads(
            "psql",
            &words(&[
                "--command=SELECT 1",
                "-f",
                "a.sql",
                "--file",
                "b.sql",
                "-f",
                "-",
            ]),
        );
        assert_eq!(
            p,
            vec![
                Payload::Script("SELECT 1".into()),
                Payload::File {
                    raw: "-f a.sql".into(),
                    path: "a.sql".into()
                },
                Payload::File {
                    raw: "-f b.sql".into(),
                    path: "b.sql".into()
                },
            ]
        );
        // `-c` always takes the next word, even one starting with `-`.
        let p = payloads("psql", &words(&["-c", "-- x\nDROP TABLE users"]));
        assert_eq!(p.len(), 1);
        let p = payloads("psql", &words(&["-o", "|rm -rf /home/dev/data"]));
        assert!(
            matches!(&p[0], Payload::Shell { command, .. } if command == "rm -rf /home/dev/data")
        );
        assert!(payloads("psql", &words(&["-h", "db", "prod", "postgres"])).is_empty());
        assert!(payloads("psql", &words(&["-v", "x=1", "-d", "prod"])).is_empty());
    }

    #[test]
    fn mysql_options() {
        let p = payloads(
            "mysql",
            &words(&["-uroot", "-psecret", "-e", "DROP DATABASE prod", "app"]),
        );
        assert_eq!(p, vec![Payload::Script("DROP DATABASE prod".into())]);
        // `-p` alone prompts: the next word is not its value.
        let p = payloads("mysql", &words(&["-p", "-eTRUNCATE orders"]));
        assert_eq!(p, vec![Payload::Script("TRUNCATE orders".into())]);
        let p = payloads(
            "mysql",
            &words(&["--execute=SELECT 1", "--init-command", "DELETE FROM t"]),
        );
        assert_eq!(
            p,
            vec![
                Payload::Script("DELETE FROM t".into()),
                Payload::Script("SELECT 1".into())
            ]
        );
        assert!(payloads("mysql", &words(&["-u", "root", "-p", "app"])).is_empty());
    }

    #[test]
    fn mongosh_sqlite_redis_and_others() {
        let p = payloads(
            "mongosh",
            &words(&[
                "mongodb://h/prod",
                "-u",
                "root",
                "-p",
                "--eval",
                "db.dropDatabase()",
            ]),
        );
        assert_eq!(p, vec![Payload::Script("db.dropDatabase()".into())]);
        let p = payloads("mongosh", &words(&["prod", "cleanup.js"]));
        assert!(matches!(&p[0], Payload::File { path, .. } if path == "cleanup.js"));

        let p = payloads(
            "sqlite3",
            &words(&["-cmd", ".shell rm -rf x", "app.db", "DROP TABLE t"]),
        );
        assert_eq!(
            p,
            vec![
                Payload::Script(".shell rm -rf x".into()),
                Payload::Script("DROP TABLE t".into())
            ]
        );
        assert!(payloads("sqlite3", &words(&["-header", "app.db"])).is_empty());

        let p = payloads("redis-cli", &words(&["-h", "cache", "-n", "2", "FLUSHALL"]));
        assert_eq!(p, vec![Payload::Script("FLUSHALL".into())]);
        assert!(payloads("redis-cli", &words(&["-h", "cache"])).is_empty());

        let p = payloads(
            "sqlcmd",
            &words(&["-S", "prod", "-Q", "DROP DATABASE prod"]),
        );
        assert_eq!(p, vec![Payload::Script("DROP DATABASE prod".into())]);
        let p = payloads("cqlsh", &words(&["-e", "DROP KEYSPACE prod"]));
        assert_eq!(p, vec![Payload::Script("DROP KEYSPACE prod".into())]);
        let p = payloads(
            "clickhouse",
            &words(&["client", "--query=TRUNCATE TABLE t"]),
        );
        assert_eq!(p, vec![Payload::Script("TRUNCATE TABLE t".into())]);
        assert!(payloads("bash", &words(&["-c", "rm -rf /"])).is_empty());
    }

    #[test]
    fn submission_uses_the_client_lexer() {
        let sub = submission(
            &[Payload::Script(
                "SELECT 1; \\! rm -rf /home/dev/data\nDELETE FROM users # WHERE id=1".into(),
            )],
            Some(Dialect::MySql),
        );
        assert!(
            sub.statements
                .iter()
                .any(|s| s.starts_with("DELETE FROM users")),
            "{sub:?}"
        );
        let sub = submission(
            &[Payload::Script("\\! rm -rf /home/dev/data".into())],
            Some(Dialect::Postgres),
        );
        assert!(
            matches!(&sub.metas[0].kind, MetaKind::Shell { command } if command == "rm -rf /home/dev/data"),
            "{sub:?}"
        );
        let sub = submission(&[Payload::Script("FLUSHALL".into())], None);
        assert_eq!(sub.statements, vec!["FLUSHALL".to_string()]);
    }
}
