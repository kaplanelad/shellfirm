//! Regex sources of the agent self-protection rules (see
//! `agent::self_protection_hits_in`).
//!
//! They live in their own file so that `build.rs` can include it and derive
//! each pattern's required literals (`SELF_PROTECTION_PREFILTERS`): the
//! rules run on every agent check, and a rule whose literals are absent from
//! the command is skipped without compiling its regex.

pub const SHELLFIRM_SUB: &str = r#"(?:^|[\s;&|(`'"])(?:[^\s;&|()'"`]*/)?shellfirm\s+(?:--log(?:=|\s+)\S+\s+)?(config|connect|init|audit)\b([^;&|\n]*)"#;

pub const PKG_UNINSTALL: &str = r"\b(?:cargo|brew|npm|pnpm|yarn|pip3?|pipx|apt|apt-get|dnf|yum|pacman)\s+(?:uninstall|remove|rm|purge|-R)\b[^;&|\n]*shellfirm";

pub const PROTECTED_FILES: &str = concat!(
    r"(?:\.config/shellfirm\b|Application Support/shellfirm\b|/shellfirm/settings\.ya?ml",
    // `.shellfirm.yaml` as a whole name (not `.shellfirm.yaml.txt`)
    r"|\.shellfirm\.ya?ml(?:$|[^\w.])|\.claude/settings(?:\.local)?\.json|\.claude\.json|\.mcp\.json",
    // the org policy (`/etc/shellfirm/policy.yaml`) and Codex's config
    r"|/etc/shellfirm\b|\.codex/config\.toml",
    r"|\.cursor/(?:hooks|mcp)\.json|\.codeium/windsurf/mcp_config\.json|zed/settings\.json",
    r"|bin/shellfirm\b|/shellfirm/audit\.log|/shellfirm/checks\b",
    // path joins in interpreter code: os.path.join(home, '.claude', 'settings.json')
    r#"|\.claude['"]?\s*[,+/]\s*['"]settings(?:\.local)?\.json|shellfirm['"]?\s*[,+/]\s*['"](?:settings\.ya?ml|checks|audit\.log)"#,
    r")",
);

pub const RC_FILES: &str = r"(?:\.(?:bashrc|bash_profile|zshrc|zprofile|zshenv|profile)\b|config\.fish\b|config\.nu\b|\.elvish/rc\.elv|Microsoft\.PowerShell_profile\.ps1)";

pub const WRITE_OP: &str = concat!(
    r"(?:(?:^|[\s;&|(`])(?:sudo\s+)?(?:rm|mv|ln|unlink|shred|truncate|tee|chmod|chown|chattr|dd|ed|ex|vi|vim|nvim|nano|emacs|perl|python[0-9.]*|ruby|node|deno|bun|osascript|patch|unzip|wget)\b",
    r"|\bsed\b[^;&|\n]*\s-[A-Za-z]*i|\byq\b[^;&|\n]*\s-i|\bjq\b[^;&|\n]*>",
    r"|\bcurl\b[^;&|\n]*\s(?:-[A-Za-z]*[oO]|--output\b|--remote-name)",
    r"|\bgit\s+(?:-C\s+\S+\s+)?(?:restore|checkout|stash|apply|am|rm|mv)\b",
    r"|\b(?:bsd)?tar\b[^;&|\n]*(?:\s-?[A-Za-z]*x|--extract|\s-C)|\b7z\s+[ex]\b",
    r"|>)",
);

pub const DEV_NULL: &str = r"[0-9&]*>{1,2}&?\s*/dev/(?:null|stdout|stderr)\b|[0-9]*>&[0-9-]";

pub const TRAP: &str = r"(?:^|[\s;&|(])trap\s+([^;&|\n]*)";

pub const ENV_OVERRIDE_0: &str = concat!(
    r"(?:^|[\s;&|(`])(?:export\s+|declare\s+-[a-zA-Z]*x[a-zA-Z]*\s+|typeset\s+-[a-zA-Z]*x[a-zA-Z]*\s+",
    r"|env\s+(?:-\S+\s+)*(?:[A-Za-z_][A-Za-z0-9_]*=\S*\s+)*)?",
    r"(XDG_CONFIG_HOME|HOME|CLAUDE_CONFIG_DIR|SHELLFIRM_[A-Z0-9_]+)=",
);

pub const ENV_OVERRIDE_1: &str = r"(?:^|[\s;&|(`])(?:set\s+-[a-zA-Z]*x[a-zA-Z]*|setenv)\s+(XDG_CONFIG_HOME|HOME|CLAUDE_CONFIG_DIR|SHELLFIRM_[A-Z0-9_]+)\b";

pub const ENV_OVERRIDE_2: &str = r"(?:^|[\s;&|(`])(?:unset\s+(?:-v\s+)?(?:[A-Za-z_][A-Za-z0-9_]*\s+)*|env\s+(?:-\S+\s+)*(?:-u|--unset)(?:=|\s+))(XDG_CONFIG_HOME|HOME|CLAUDE_CONFIG_DIR|SHELLFIRM_[A-Z0-9_]+)\b";

pub const RC_ENV_LINE: &str = r"\b(?:XDG_CONFIG_HOME|HOME|CLAUDE_CONFIG_DIR|SHELLFIRM_[A-Z0-9_]+|PROMPT_COMMAND|precmd_functions|preexec_functions)\s*=|\btrap\b|\bunset\s+-f\b|\bzle\s+-[ADN]\b|\badd-zsh-hook\b|\bset\s+-[a-zA-Z]*x[a-zA-Z]*\s+(?:XDG_CONFIG_HOME|HOME)\b";

pub const HOOK_TAMPER_0: &str =
    r"\b(?:unset\s+(?:-f\s+)?|unfunction\s+|functions\s+(?:-e|--erase)\s+)[^;&|\n]*shellfirm";

pub const HOOK_TAMPER_1: &str = r"\bzle\s+-[ADN]\b[^;&|\n]*accept-line";

pub const HOOK_TAMPER_2: &str = r"\badd-zsh-hook\s+-[dD]\b";

pub const HOOK_TAMPER_3: &str =
    r"\bbind\s+-r\b|\bshopt\s+-u\s+extdebug\b|\bset\s+\+o\s+functrace\b";

pub const HOOK_TAMPER_4: &str = r"(?:^|[\s;&|(])(?:export\s+)?PROMPT_COMMAND\s*=|\bpreexec_functions\s*=|\bprecmd_functions\s*=";

pub const HOOK_TAMPER_5: &str = r"\balias\s+shellfirm=|\bunalias\b[^;&|\n]*shellfirm|(?:^|[\s;&|(])(?:function\s+)?shellfirm\s*\(\s*\)";

pub const AGENT_BYPASS: &str = concat!(
    r"\bdisableAllHooks\b",
    r#"|(?:^|[\s;&|(`'"])(?:[^\s;&|()'"`]*/)?(?:claude|codex|cursor-agent|gemini)\s[^;&|\n]*?"#,
    r"(?:--settings\b|--setting-sources\b|--bare\b|--dangerously-skip-permissions\b",
    r"|--allow-dangerously-skip-permissions\b|--permission-mode(?:=|\s+)['\x22]?bypassPermissions",
    r"|--dangerously-bypass-approvals-and-sandbox\b|--yolo\b)",
);

pub const OTHER_VERSION: &str = concat!(
    r"\bcargo\s+(?:\+\S+\s+)?install\b[^;&|\n]*(?:shellfirm@|\bshellfirm\b[^;&|\n]*\s--(?:version|vers|git|path|rev|tag|branch)\b",
    r"|\s--(?:version|vers|git|path|rev|tag|branch)\b[^;&|\n]*\bshellfirm\b)",
    r"|\b(?:npm|pnpm|yarn|bun)\s+(?:i|install|add|global\s+add)\b[^;&|\n]*(?:@shellfirm/[\w.-]+|\bshellfirm)@\S",
    r"|\bbrew\s+(?:install|reinstall|switch|link|pin)\b[^;&|\n]*\bshellfirm@",
    r"|\bpipx?\s+install\b[^;&|\n]*\bshellfirm\s*[=<>~!]=",
);

pub const BULK_REWRITE: &str = concat!(
    r"\bgit\s+(?:-C\s+\S+\s+)?(?:apply|am)\b",
    r"|\bgit\s+(?:-C\s+\S+\s+)?stash\b[^;&|\n]*\s(?:-u|--include-untracked|-a|--all)\b",
    r"|\bgit\s+(?:-C\s+\S+\s+)?restore\b[^;&|\n]*--source",
    r"|(?:^|[\s;&|(`])patch\b",
    r"|\b(?:bsd)?tar\b[^;&|\n]*(?:\s-?[A-Za-z]*x[A-Za-z]*\b|--extract)",
    r"|\bunzip\b|\b7z\s+[ex]\b",
);

pub const EXTRACT_ELSEWHERE: &str =
    r"\b(?:bsd)?tar\b[^;&|\n]*\s(?:-C|--directory)(?:=|\s*)\S|\bunzip\b[^;&|\n]*\s-d\s*\S";

/// Commands that install something that runs code later: git settings that
/// execute a program (pager, editor, ssh command, fsmonitor, hooks path,
/// filters, `!` aliases) in any scope, `crontab FILE|-`, and enabling a
/// systemd / launchd unit.
pub const PERSISTENCE_CMD: &str = concat!(
    r#"(?:^|[\s;&|(`])git\s+(?:-c\s+\S+\s+)*config\s+(?:--(?:global|system|local|worktree|add|replace-all)\s+|(?:--file|-f)\s+\S+\s+)*"#,
    r#"(?i:core\.(?:pager|editor|sshcommand|fsmonitor|hookspath|askpass|gitproxy)|sequence\.editor|interactive\.difffilter"#,
    r#"|diff\.[\w.-]+\.(?:textconv|command)|filter\.[\w.-]+\.(?:clean|smudge|process)|credential\.(?:[\w.:/-]+\.)?helper|gpg\.program)\s+\S"#,
    r#"|(?:^|[\s;&|(`])git\s+(?:-c\s+\S+\s+)*config\s+(?:--\S+\s+)*alias\.[\w.-]+\s+['"]?!"#,
    r"|(?:^|[\s;&|(`])crontab\s+(?:-u\s+\S+\s+)?(?:-|[^\s;&|<>-][^\s;&|<>]*)(?:$|[\s;&|)])",
    r"|(?:^|[\s;&|(`])systemctl\b[^;&|\n]*\s(?:enable|reenable|link|add-wants|add-requires)\b",
    r"|(?:^|[\s;&|(`])launchctl\s+(?:load|bootstrap|enable|submit)\b",
);

/// Every pattern above (build.rs derives a prefilter for each).
#[cfg_attr(not(test), allow(dead_code))]
pub const ALL: &[&str] = &[
    SHELLFIRM_SUB,
    PKG_UNINSTALL,
    PROTECTED_FILES,
    RC_FILES,
    WRITE_OP,
    DEV_NULL,
    TRAP,
    ENV_OVERRIDE_0,
    ENV_OVERRIDE_1,
    ENV_OVERRIDE_2,
    RC_ENV_LINE,
    HOOK_TAMPER_0,
    HOOK_TAMPER_1,
    HOOK_TAMPER_2,
    HOOK_TAMPER_3,
    HOOK_TAMPER_4,
    HOOK_TAMPER_5,
    AGENT_BYPASS,
    OTHER_VERSION,
    BULK_REWRITE,
    EXTRACT_ELSEWHERE,
    PERSISTENCE_CMD,
];
