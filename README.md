<p align="center">
<img src="https://github.com/kaplanelad/shellfirm/actions/workflows/ci.yaml/badge.svg"/>
<img src="https://github.com/kaplanelad/shellfirm/actions/workflows/release.yml/badge.svg"/>
</p>
  
# shellfirm

<div align="center">
<h1>Opppppsss <b>you</b> did it again? :scream: :scream: :cold_sweat:</h1>
</div>

How do I save myself from myself?
* `rm -rf *`
* `git reset --hard` before hitting the enter key?
* `kubectl delete ns` Stop! You are going to delete a lot of resources.
* `docker system prune -a` Bye bye, all your images and containers.
* `aws s3 rb` Deleting an entire S3 bucket?
* And many more!

`shellfirm` will intercept any risky patterns and immediately prompt a small challenge that will double verify your action, think of it as a captcha for your terminal.

```bash
$ rm -rf /
#######################
# RISKY COMMAND FOUND #
#######################
* You are going to delete everything in the path.

> Safe alternative: rm -ri /  (interactive mode, confirm each file)

Solve the challenge: 8 + 0 = ? (^C to cancel)
```

## Features

### Context-Aware Protection
shellfirm detects *where* you're running and automatically escalates challenge difficulty:

| Signal | Risk Level | Example |
|--------|-----------|---------|
| SSH session | Elevated | Harder challenge when remotely connected |
| Root user | Critical | Hardest challenge to prevent root-level mistakes |
| Protected git branch | Elevated | Extra caution on `main`, `master`, `release/*` |
| Production Kubernetes | Critical | Safeguards for prod clusters |
| Custom env vars | Configurable | Flag `ENVIRONMENT=production` as critical |

### Safe Alternative Suggestions
When a risky command is detected, shellfirm suggests a safer alternative:

```
$ git push --force origin main
#######################
# RISKY COMMAND FOUND #
#######################
* Force push can overwrite remote history.

> Safe alternative: git push --force-with-lease origin main
  (Only force-pushes if your local ref matches the remote, preventing accidental overwrites)
```

### Severity Levels
Every check has a severity level that indicates how critical the matched pattern is:

| Severity | Description | Examples |
|----------|-------------|----------|
| `Critical` | Irreversible, catastrophic actions | `rm -rf /`, `DROP DATABASE`, `mkfs`, `terraform apply -auto-approve` |
| `High` | Dangerous but scoped actions | `git push --force`, `docker system prune -a`, cloud resource deletion |
| `Medium` | Potentially risky, context-dependent | `git cherry-pick`, `chmod`, `docker network rm` |
| `Low` | Informational, strict-mode guards | `git add .`, `git commit --all`, `git tag -a` |
| `Info` | Advisory-only | Custom checks for team conventions |

You can set a **minimum severity threshold** so that low-severity checks are silently skipped (but still logged to audit):

```bash
shellfirm config severity          # Interactive selection
shellfirm config severity High     # Only challenge on High and Critical
shellfirm config severity None     # Disable filtering (challenge on all)
```

Or edit `~/.shellfirm/settings.yaml` directly:
```yaml
min_severity: High
```

When `min_severity` is not set (the default), all severities trigger a challenge.

### Project-Level Policies
Teams can share safety rules via a `.shellfirm.yaml` file in their repository:

```yaml
version: "1"
deny:
  - "git:force_push"
overrides:
  - id: "fs:recursively_delete"
    min_challenge: Yes
```

Policies are **additive-only** -- they can make shellfirm stricter but never weaker. Rules are inherited up the directory tree, so a monorepo can have different policies per subdirectory.

### Audit Trail
Track every intercepted command and your decision:

```bash
shellfirm audit show
# [2026-02-15T10:00:00Z] git push -f | matched: git:force_push | challenge: Math | ALLOWED | ctx: branch=main
```

### Expanded Coverage
Built-in patterns cover **9 ecosystems**: filesystem, git, Kubernetes, Terraform, Heroku, Docker, AWS, GCP/Azure, and databases.

---

## How Does It Work?

`shellfirm` evaluates every shell command before execution. If a risky pattern is detected, you get an immediate challenge prompt. The pipeline:

1. **Pattern matching** -- regex-based detection across compound commands (`&&`, `||`, `|`, `;`)
2. **Severity filtering** -- checks below `min_severity` are skipped (but still audit-logged)
3. **Context detection** -- SSH, root, git branch, Kubernetes context, environment variables
4. **Policy enforcement** -- project `.shellfirm.yaml` rules merged with user settings
5. **Challenge escalation** -- difficulty scales with risk level
6. **Safe alternatives** -- actionable suggestion shown alongside the warning
7. **Audit logging** -- every decision recorded (optional)

## Example
![](./docs/media/example.gif)

---

## Installation

### Via Homebrew
```bash
brew tap kaplanelad/tap && brew install shellfirm
```

### Via Cargo
```bash
cargo install shellfirm
```

Or download the binary from the [releases page](https://github.com/kaplanelad/shellfirm/releases).

Verify:
```bash
shellfirm --version
```

---

## Shell Setup

One command — auto-detects your shell and writes the hook to your rc file:

```bash
shellfirm init --install
```

That's it. Restart your shell (or `source` your rc file) and you're protected.

To specify the shell explicitly:
```bash
shellfirm init zsh --install
shellfirm init bash --install
shellfirm init fish --install
```

Supported shells: **Zsh**, **Bash**, **Fish**, **Nushell**, **PowerShell**, **Elvish**, **Xonsh**, **Oils (OSH/YSH)**.

### Verify
```bash
git reset --hard  # Should trigger shellfirm!
```

<details>
<summary>Manual setup (print hook without installing)</summary>

If you prefer to add the hook yourself, run `shellfirm init` without `--install` to
print the hook code to stdout:

```bash
# Zsh / Bash / Oils — add this line to your rc file:
eval "$(shellfirm init zsh)"

# Fish — add this line to ~/.config/fish/config.fish:
shellfirm init fish | source

# Nushell / PowerShell / Elvish / Xonsh — run and paste output into your config:
shellfirm init nushell
shellfirm init powershell
shellfirm init elvish
shellfirm init xonsh
```

| Shell | RC File |
|-------|---------|
| Zsh | `~/.zshrc` |
| Bash | `~/.bashrc` |
| Fish | `~/.config/fish/config.fish` |
| Nushell | `$nu.config-path` (run `config nu` to edit) |
| PowerShell | `$PROFILE` (run `notepad $PROFILE` to edit) |
| Elvish | `~/.config/elvish/rc.elv` |
| Xonsh | `~/.xonshrc` |
| Oils (OSH/YSH) | `~/.config/oils/oshrc` |

</details>

<details>
<summary>Oh My Zsh plugin</summary>

```sh
curl https://raw.githubusercontent.com/kaplanelad/shellfirm/main/shell-plugins/shellfirm.plugin.oh-my-zsh.zsh \
  --create-dirs -o ${ZSH_CUSTOM:-~/.oh-my-zsh/custom}/plugins/shellfirm/shellfirm.plugin.zsh
```

Add `shellfirm` to the plugin list in `~/.zshrc`:
```bash
plugins=(... shellfirm)
```
</details>

---

## Configuration

### Challenge Types

| Type | Description |
|------|------------|
| `Math` | Solve a simple arithmetic problem (default) |
| `Enter` | Press Enter to confirm |
| `Yes` | Type "yes" to confirm |

```bash
shellfirm config challenge   # Interactive selection
```

### Context-Aware Settings

Edit `~/.shellfirm/settings.yaml` to configure context detection:

```yaml
context:
  protected_branches:
    - main
    - master
    - "release/*"
  production_k8s_patterns:
    - "prod"
    - "production"
  production_env_vars:
    ENVIRONMENT: "production"
    RAILS_ENV: "production"
    NODE_ENV: "production"
  escalation:
    elevated: Enter    # Elevated risk -> at least Enter challenge
    critical: Yes      # Critical risk -> at least Yes challenge
audit_enabled: true
```

### Custom Checks

Add your own patterns by placing YAML files in `~/.shellfirm/checks/`:

```yaml
# ~/.shellfirm/checks/my-team.yaml
- from: internal
  test: deploy-tool nuke
  description: "This will destroy the deployment."
  id: internal:deploy_nuke
  severity: Critical
  alternative: deploy-tool rollback
  alternative_info: "Rolls back to the previous version safely."
```

If `severity` is omitted, it defaults to `Medium`.

### Manage Checks

```bash
shellfirm config update-groups  # Enable/disable check groups
shellfirm config ignore         # Ignore specific patterns
shellfirm config deny           # Hard-deny patterns (no challenge, just block)
shellfirm config severity       # Set minimum severity threshold
shellfirm config show           # Display current configuration
shellfirm config reset          # Reset to defaults
```

---

## Team Adoption (Project Policies)

### Create a Policy

```bash
cd your-project
shellfirm policy init    # Creates .shellfirm.yaml template
```

### Example `.shellfirm.yaml`

```yaml
version: "1"

# Hard-deny these patterns (team members cannot override)
deny:
  - "git:force_push"
  - "fs:recursively_delete"

# Escalate challenge for specific patterns
overrides:
  - id: "kubernetes:delete_namespace"
    min_challenge: Yes
  - id: "git:reset_hard"
    min_challenge: Enter
    branches:
      - main
      - "release/*"
```

### Validate

```bash
shellfirm policy validate
# .shellfirm.yaml: valid
```

### How Policies Work

- Policies are **additive-only**: they can make shellfirm stricter but never weaker
- Files are discovered by walking up the directory tree from `cwd`
- Commit `.shellfirm.yaml` to your repository so the whole team shares the same safety rules

---

## Audit Trail

Enable auditing in your settings:
```yaml
audit_enabled: true
```

Commands:
```bash
shellfirm audit show    # View the log
shellfirm audit clear   # Clear the log
```

Each entry records: timestamp, command, matched patterns, severity, challenge type, outcome (ALLOWED/BLOCKED/DENIED/SKIPPED), and context labels. Checks that matched but were below `min_severity` are logged with a `SKIPPED` outcome.

---

## Architecture

### Testing

shellfirm uses a three-tier testing strategy with full sandboxing (zero real system access):

- **Tier 1 -- Pure Logic** (27 tests): Pattern matching, challenge escalation, policy merging, command splitting
- **Tier 2 -- Sandboxed Integration** (17 tests): Full pipeline with mock `Environment` and `Prompter` traits
- **Tier 3 -- Decision Matrix** (YAML-driven scenarios): Product behavior validated from a single `matrix.yaml` file

```bash
cargo test   # Runs all 102 tests, fully sandboxed
```

### Dependency Injection

All I/O is abstracted through two traits:
- `Environment` -- filesystem, env vars, command execution
- `Prompter` -- user interaction (challenges)

This enables complete test isolation without touching the real filesystem, network, or terminal.

---

## Built-in Check Coverage

| Ecosystem | Severities | Examples |
|-----------|------------|----------|
| **Filesystem** | Critical -- High | `rm -rf`, `chmod -R`, `mkfs`, `dd` |
| **Filesystem (strict)** | Medium | `rm`, `rmdir`, `chmod` |
| **Git** | High -- Medium | `force push`, `reset --hard`, `clean -fd`, `cherry-pick` |
| **Git (strict)** | Low -- Medium | `git add .`, `git commit --all`, `git tag -a` |
| **Kubernetes** | Critical | `delete namespace` |
| **Kubernetes (strict)** | High | `delete`, `scale`, `rollout`, `set` |
| **Terraform** | Critical -- High | `-auto-approve`, `state mv`, `force-unlock` |
| **Docker** | High -- Medium | `system prune -a`, `rm -f`, `volume rm` |
| **AWS** | High | `s3 rb`, `ec2 terminate`, `rds delete`, `iam delete-user` |
| **GCP** | High | `compute instances delete`, `sql instances delete` |
| **Azure** | High | `group delete`, `vm delete`, `keyvault delete` |
| **Database** | Critical -- High | `DROP DATABASE`, `DROP TABLE`, `TRUNCATE`, `FLUSHALL` |
| **Heroku** | Critical -- Medium | `apps:destroy`, `addons:destroy`, `ps:restart` |
| **Network** | Critical -- High | `iptables -F`, `ufw disable`, `systemctl stop networking` |

---

## Contributing

```bash
# Clone and build
git clone https://github.com/kaplanelad/shellfirm.git
cd shellfirm
cargo build

# Run tests (fully sandboxed, safe to run anywhere)
cargo test

# Add a new check pattern
# 1. Add entry to shellfirm/checks/<ecosystem>.yaml
# 2. Add test file to shellfirm/tests/checks/<id>.yaml
# 3. Run: cargo test test_missing_patterns_coverage
```

## License

MIT
