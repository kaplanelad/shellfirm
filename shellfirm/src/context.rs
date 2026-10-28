//! Runtime context detection.
//!
//! Detects environment signals (SSH, root, git branch, k8s context, etc.)
//! and computes a [`RiskLevel`] used to escalate challenge severity.
//!
//! Detection is **command-aware** when it goes through
//! [`detect_for_command`]: what the command itself targets wins over the
//! ambient state of the shell. For example `git push -f origin main` is
//! judged by the push target (`main`), not by the branch that happens to be
//! checked out, and `kubectl --context prod-eu delete ...` is judged by
//! `prod-eu`, not by `kubectl config current-context`.
//!
//! ## Production k8s context matching
//!
//! Entries of `context.production_k8s_patterns` are matched against the
//! context name on **segment boundaries**, case-insensitively. A context
//! name is split into segments on every non-alphanumeric character
//! (`-`, `_`, `/`, `:`, `.`, `@`, ...), and a pattern matches when its own
//! segments appear consecutively in the context. With the default patterns
//! (`prod`, `production`, `prd`, `live`):
//!
//! | context                                  | production? |
//! |------------------------------------------|-------------|
//! | `prod-eu`, `gke_acme_prod_euw1`, `PROD`  | yes         |
//! | `arn:aws:eks:us-east-1:1:cluster/prd-a`  | yes         |
//! | `preprod`, `k8s-products-dev`            | no          |
//! | `reproduce-bug`, `olive-test`            | no          |
//!
//! `preprod` is intentionally **not** production: it is a single segment
//! that merely contains `prod`. A pattern containing `*` or `?` is matched
//! as a glob against the whole context name instead (so `*prod*` opts back
//! into substring matching).

use std::path::PathBuf;

use serde_derive::{Deserialize, Serialize};
use tracing::debug;

use crate::{
    checks::Check,
    config::{Challenge, ResolvedSettings, Settings},
    env::{CommandOutcome, Environment},
    policy::MergedPolicy,
};

/// Timeout for `git rev-parse --abbrev-ref HEAD`.
const GIT_TIMEOUT_MS: u64 = 200;
/// Timeout for `kubectl config current-context`. kubectl (and wrappers such
/// as kubecolor) regularly take more than 100ms on a loaded laptop; a
/// timeout no longer silently means "not production" — see
/// [`RuntimeContext::k8s_unknown`].
const K8S_TIMEOUT_MS: u64 = 300;

/// Program names whose presence in a command makes the k8s context relevant.
const K8S_PROGRAMS: &[&str] = &[
    "kubectl",
    "k",
    "kubecolor",
    "oc",
    "helm",
    "helmfile",
    "flux",
    // Backups / restores of the cluster in the current context
    // (`--kubecontext` picks another).
    "velero",
];

/// Risk level computed from environment context signals.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub enum RiskLevel {
    /// No risk signals detected.
    #[default]
    Normal,
    /// Moderate signals: SSH session, unknown k8s context, etc.
    Elevated,
    /// High-risk signals: root, production k8s, protected branch, production env.
    Critical,
}

/// Snapshot of environment context at the time a command is evaluated.
#[derive(Debug, Clone, Default)]
#[allow(clippy::struct_excessive_bools)]
pub struct RuntimeContext {
    pub is_ssh: bool,
    pub is_root: bool,
    /// `true` when root comes from a `sudo`/`doas` prefix in the command
    /// rather than from the process' effective uid.
    pub root_via_sudo: bool,
    /// The wrapper that runs the command as root (`sudo`, `doas`, `su`,
    /// `pkexec`, `runuser`, `nsenter`), when [`Self::root_via_sudo`].
    pub root_via: Option<String>,
    /// The k8s context a switch earlier in the line tried to select when
    /// [`Self::k8s_context`] was kept because that switch may have failed
    /// (`kubectx dev; kubectl delete …`).
    pub k8s_switch_attempt: Option<String>,
    /// The branch the command runs on: the checked-out branch, or the branch
    /// an earlier `git checkout|switch B` in the same line switches to.
    pub git_branch: Option<String>,
    /// `true` when [`Self::git_branch`] comes from a `git checkout|switch`
    /// earlier in the same command line.
    pub git_branch_switched: bool,
    /// `true` when the checked-out branch could not be determined (git did
    /// not answer in time). Treated as [`RiskLevel::Elevated`] — never
    /// silently "normal".
    pub git_unknown: bool,
    /// Branches the command explicitly targets (push destination,
    /// `git branch -D <name>`, ...).
    pub git_targets: Vec<String>,
    /// `true` when the checked-out branch is irrelevant for protected-branch
    /// escalation: every git invocation names its targets explicitly (e.g.
    /// `git push -f origin feature/x` while sitting on `main`) or only does
    /// local work that neither rewrites, pushes nor deletes the branch
    /// (`cherry-pick`, `rebase -i`, `stash clear`, `gc`, ...).
    pub git_ignore_current_branch: bool,
    /// The command pushes every branch (`git push --all` / `--mirror`).
    pub git_push_all: bool,
    /// A push target that is only known when the line runs (`origin $B`
    /// with `B` unset, `$(cat file)`, `"$@"`), in a repository that has a
    /// protected branch: it may be one of them. Shown as `target=unknown`
    /// (never as a branch name it may not be) and escalated like a
    /// protected branch.
    pub git_target_unknown: bool,
    pub k8s_context: Option<String>,
    /// `true` when the k8s context could not be determined (kubectl timed
    /// out). Treated as [`RiskLevel::Elevated`] — never silently "normal".
    pub k8s_unknown: bool,
    /// `true` when the k8s context was not checked (`--no-context` and no
    /// kubeconfig file to read). Shown as `k8s=not checked`.
    pub k8s_not_checked: bool,
    /// k8s namespace named by the command (`-n prod`, `kubens prod`).
    pub k8s_namespace: Option<String>,
    /// AWS profile (`--profile`, `AWS_PROFILE`).
    pub aws_profile: Option<String>,
    /// Terraform workspace (`TF_WORKSPACE`, `terraform workspace select`).
    pub tf_workspace: Option<String>,
    /// `true` when the terraform working directory is only known when the
    /// command runs (`terraform -chdir=$ENV destroy`), so its workspace is
    /// unknown. Treated as [`RiskLevel::Elevated`].
    pub tf_unknown: bool,
    /// gcloud project (`--project`, `gcloud config set project`,
    /// `CLOUDSDK_CORE_PROJECT`).
    pub gcp_project: Option<String>,
    /// Azure subscription (`--subscription`, `az account set`).
    pub azure_subscription: Option<String>,
    /// A Kubernetes cluster the command deletes or changes by name
    /// (`eksctl delete cluster --name prod`, `gcloud container clusters
    /// delete prod-gke`).
    pub cluster: Option<String>,
    /// Hosts the command runs on remotely (`ssh host ...`).
    pub remote_hosts: Vec<String>,
    /// `context.sensitive_paths` entries that the command deletes or
    /// overwrites (or deletes a parent of).
    pub sensitive_paths: Vec<String>,
    pub env_signals: Vec<String>,
    pub risk_level: RiskLevel,
    /// Human-readable labels shown in the banner (e.g. "branch=main").
    pub labels: Vec<String>,
}

/// User-configurable context settings (stored in `settings.yaml`).
#[derive(Debug, Deserialize, Serialize, Clone)]
pub struct ContextConfig {
    #[serde(default = "default_protected_branches")]
    pub protected_branches: Vec<String>,
    #[serde(default = "default_production_k8s_patterns")]
    pub production_k8s_patterns: Vec<String>,
    #[serde(default = "default_production_env_vars")]
    pub production_env_vars: std::collections::BTreeMap<String, String>,
    #[serde(default)]
    pub sensitive_paths: Vec<String>,
    #[serde(default)]
    pub escalation: EscalationConfig,
}

fn default_protected_branches() -> Vec<String> {
    vec![
        "main".into(),
        "master".into(),
        "production".into(),
        "release/*".into(),
    ]
}

fn default_production_k8s_patterns() -> Vec<String> {
    vec![
        "prod".into(),
        "production".into(),
        "prd".into(),
        "live".into(),
    ]
}

fn default_production_env_vars() -> std::collections::BTreeMap<String, String> {
    let mut m = std::collections::BTreeMap::new();
    m.insert("NODE_ENV".into(), "production".into());
    m.insert("RAILS_ENV".into(), "production".into());
    m.insert("ENVIRONMENT".into(), "production".into());
    m
}

impl Default for ContextConfig {
    fn default() -> Self {
        Self {
            protected_branches: default_protected_branches(),
            production_k8s_patterns: default_production_k8s_patterns(),
            production_env_vars: default_production_env_vars(),
            sensitive_paths: vec![],
            escalation: EscalationConfig::default(),
        }
    }
}

/// Maps risk levels to the minimum challenge type.
///
/// These are *floors*: the context can only make a challenge stricter
/// (`Enter < Math < Yes`), never weaker.
#[derive(Debug, Deserialize, Serialize, Clone)]
pub struct EscalationConfig {
    #[serde(default = "default_elevated_challenge")]
    pub elevated: Challenge,
    #[serde(default = "default_critical_challenge")]
    pub critical: Challenge,
}

const fn default_elevated_challenge() -> Challenge {
    Challenge::Math
}
const fn default_critical_challenge() -> Challenge {
    Challenge::Yes
}

impl Default for EscalationConfig {
    fn default() -> Self {
        Self {
            elevated: default_elevated_challenge(),
            critical: default_critical_challenge(),
        }
    }
}

impl RuntimeContext {
    /// Return a filtered copy that only contains signals relevant to the
    /// matched check groups.
    ///
    /// **Global signals** (`is_ssh`, `is_root`, `env_signals`, remote hosts
    /// and sensitive paths) are always kept — they apply regardless of what
    /// command matched.
    ///
    /// **Domain signals** are kept only when the corresponding group is
    /// present in `matched_groups`:
    /// - git branch / targets / push-all → `"git"`
    /// - k8s context / namespace → `"kubernetes"`
    /// - AWS profile → `"aws"`, terraform workspace → `"terraform"`,
    ///   gcloud project → `"gcp"`, Azure subscription → `"azure"` (the cloud
    ///   signals are also kept for `"terraform"`: `IaC` runs against them)
    ///
    /// Labels and `risk_level` are recomputed from the kept signals.
    #[must_use]
    pub fn filter_for_groups(
        &self,
        matched_groups: &std::collections::HashSet<&str>,
        config: &ContextConfig,
    ) -> Self {
        let keep = |g: &str| matched_groups.contains(g);
        let keep_git = keep("git");
        let keep_k8s = keep("kubernetes");
        let keep_iac = keep("terraform");
        let opt = |k: bool, v: &Option<String>| if k { v.clone() } else { None };

        let mut filtered = Self {
            is_ssh: self.is_ssh,
            is_root: self.is_root,
            root_via_sudo: self.root_via_sudo,
            root_via: self.root_via.clone(),
            k8s_switch_attempt: opt(keep_k8s, &self.k8s_switch_attempt),
            git_branch: opt(keep_git, &self.git_branch),
            git_branch_switched: keep_git && self.git_branch_switched,
            git_unknown: keep_git && self.git_unknown,
            git_targets: if keep_git {
                self.git_targets.clone()
            } else {
                Vec::new()
            },
            // Without the git signals the command does not act on the
            // branch (`rm -rf build && git reset --hard` on `main`).
            git_ignore_current_branch: !keep_git || self.git_ignore_current_branch,
            git_push_all: keep_git && self.git_push_all,
            git_target_unknown: keep_git && self.git_target_unknown,
            k8s_context: opt(keep_k8s, &self.k8s_context),
            k8s_unknown: keep_k8s && self.k8s_unknown,
            k8s_not_checked: keep_k8s && self.k8s_not_checked,
            k8s_namespace: opt(keep_k8s, &self.k8s_namespace),
            // IaC tools (terraform, pulumi, …) act on the cloud account
            // their provider credentials point at.
            aws_profile: opt(keep("aws") || keep_iac, &self.aws_profile),
            tf_workspace: opt(keep_iac, &self.tf_workspace),
            tf_unknown: keep_iac && self.tf_unknown,
            gcp_project: opt(keep("gcp") || keep_iac, &self.gcp_project),
            azure_subscription: opt(keep("azure") || keep_iac, &self.azure_subscription),
            cluster: opt(
                keep_k8s || keep("aws") || keep("gcp") || keep("azure"),
                &self.cluster,
            ),
            remote_hosts: self.remote_hosts.clone(),
            sensitive_paths: self.sensitive_paths.clone(),
            env_signals: self.env_signals.clone(),
            risk_level: RiskLevel::Normal,
            labels: Vec::new(),
        };
        filtered.refresh(config);
        filtered
    }

    /// Recompute `labels` and `risk_level` from the signal fields.
    pub fn refresh(&mut self, config: &ContextConfig) {
        self.labels = self.build_labels();
        self.risk_level = compute_risk_level(self, config);
    }

    fn build_labels(&self) -> Vec<String> {
        let mut labels = Vec::new();
        if self.is_ssh {
            labels.push("ssh=true".into());
        }
        if self.is_root {
            labels.push(if self.root_via_sudo {
                format!("root={}", self.root_via.as_deref().unwrap_or("sudo"))
            } else {
                "root=true".into()
            });
        }
        if let Some(ref branch) = self.git_branch {
            let branch = escape_invisible(branch);
            labels.push(if self.git_branch_switched {
                format!("branch={branch} (switched in this command)")
            } else {
                format!("branch={branch}")
            });
        } else if self.git_unknown {
            labels.push("git=unknown".into());
        }
        if !self.git_targets.is_empty() {
            let t: Vec<String> = self
                .git_targets
                .iter()
                .map(|b| escape_invisible(b))
                .collect();
            labels.push(format!("target={}", t.join(",")));
        }
        if self.git_target_unknown {
            labels.push("target=unknown".into());
        }
        if self.git_push_all {
            labels.push("push=all-branches".into());
        }
        if let Some(ref k8s) = self.k8s_context {
            labels.push(self.k8s_switch_attempt.as_ref().map_or_else(
                || format!("k8s={}", escape_invisible(k8s)),
                |to| {
                    format!(
                        "k8s={} (kept: the switch to {} may fail)",
                        escape_invisible(k8s),
                        escape_invisible(to)
                    )
                },
            ));
        } else if self.k8s_unknown {
            labels.push("k8s=unknown".into());
        } else if self.k8s_not_checked {
            labels.push("k8s=not checked".into());
        }
        for (key, v) in [
            ("namespace", &self.k8s_namespace),
            ("aws-profile", &self.aws_profile),
            ("tf-workspace", &self.tf_workspace),
            ("gcp-project", &self.gcp_project),
            ("azure-subscription", &self.azure_subscription),
            ("cluster", &self.cluster),
        ] {
            if let Some(v) = v {
                labels.push(format!("{key}={}", escape_invisible(v)));
            }
        }
        if self.tf_workspace.is_none() && self.tf_unknown {
            labels.push("tf-workspace=unknown".into());
        }
        for host in &self.remote_hosts {
            labels.push(format!("remote={}", escape_invisible(host)));
        }
        for p in &self.sensitive_paths {
            labels.push(format!("sensitive-path={}", escape_invisible(p)));
        }
        for sig in &self.env_signals {
            labels.push(format!("env:{}", escape_invisible(sig)));
        }
        labels
    }

    /// The branches whose protection status matters for this command.
    fn branches_to_evaluate(&self) -> Vec<&str> {
        let mut out: Vec<&str> = self.git_targets.iter().map(String::as_str).collect();
        if !self.git_ignore_current_branch {
            if let Some(ref b) = self.git_branch {
                if !out.contains(&b.as_str()) {
                    out.push(b);
                }
            }
        }
        out
    }

    /// Human-readable reasons behind the risk level, each tagged with the
    /// level it contributes. Empty when the context is [`RiskLevel::Normal`].
    #[must_use]
    #[allow(clippy::too_many_lines)]
    pub fn risk_reasons(&self, config: &ContextConfig) -> Vec<(RiskLevel, String)> {
        let mut reasons = Vec::new();
        if self.is_root {
            reasons.push((
                RiskLevel::Critical,
                if self.root_via_sudo {
                    format!(
                        "runs as root ({})",
                        self.root_via.as_deref().unwrap_or("sudo")
                    )
                } else {
                    "running as root".to_string()
                },
            ));
        }
        for branch in self.branches_to_evaluate() {
            if branch_matches_any(branch, &config.protected_branches) {
                reasons.push((
                    RiskLevel::Critical,
                    format!("protected branch `{}`", escape_invisible(branch)),
                ));
            }
        }
        if self.git_target_unknown && !config.protected_branches.is_empty() {
            reasons.push((
                RiskLevel::Critical,
                "push target unknown until the line runs (this repository has a protected branch)"
                    .to_string(),
            ));
        }
        if self.git_push_all && !config.protected_branches.is_empty() {
            reasons.push((
                RiskLevel::Critical,
                "pushes all branches (--all/--mirror)".to_string(),
            ));
        }
        if let Some(ref k8s) = self.k8s_context {
            if matches_any_pattern(k8s, &config.production_k8s_patterns) {
                reasons.push((
                    RiskLevel::Critical,
                    format!("production k8s context `{}`", escape_invisible(k8s)),
                ));
            }
        }
        for (what, v) in [
            ("k8s namespace", &self.k8s_namespace),
            ("AWS profile", &self.aws_profile),
            ("terraform workspace", &self.tf_workspace),
            ("gcloud project", &self.gcp_project),
            ("Azure subscription", &self.azure_subscription),
            ("cluster", &self.cluster),
        ] {
            if let Some(v) = v {
                if matches_any_pattern(v, &config.production_k8s_patterns) {
                    reasons.push((
                        RiskLevel::Critical,
                        format!("production {what} `{}`", escape_invisible(v)),
                    ));
                }
            }
        }
        for host in &self.remote_hosts {
            if matches_any_pattern(host, &config.production_k8s_patterns) {
                reasons.push((
                    RiskLevel::Critical,
                    format!("runs on production host `{}`", escape_invisible(host)),
                ));
            }
        }
        for p in &self.sensitive_paths {
            reasons.push((
                RiskLevel::Critical,
                format!("touches sensitive path `{}`", escape_invisible(p)),
            ));
        }
        for sig in &self.env_signals {
            reasons.push((
                RiskLevel::Critical,
                format!("production environment ({sig})"),
            ));
        }
        if self.git_branch.is_none() && self.git_unknown {
            reasons.push((
                RiskLevel::Elevated,
                "git branch unknown (git did not answer in time)".to_string(),
            ));
        }
        if self.k8s_context.is_none() && self.k8s_unknown {
            reasons.push((
                RiskLevel::Elevated,
                "k8s context unknown (kubectl did not answer in time)".to_string(),
            ));
        }
        if self.tf_workspace.is_none() && self.tf_unknown {
            reasons.push((
                RiskLevel::Elevated,
                "terraform workspace unknown (its directory is only known when the command runs)"
                    .to_string(),
            ));
        }
        if self.is_ssh {
            reasons.push((RiskLevel::Elevated, "SSH session".to_string()));
        }
        reasons
    }
}

/// Detect runtime context from the given environment, without looking at
/// any command (used by `status` and other non-command callers).
///
/// Every signal is probed, including the k8s context.
pub fn detect(env: &dyn Environment, config: &ContextConfig) -> RuntimeContext {
    detect_inner(env, config, None)
}

/// Detect runtime context for a specific command line.
///
/// On top of [`detect`], this honours what the command itself targets:
/// - `git push [-f] origin main`, `git push origin +main`, `HEAD:main`,
///   `git push --delete origin main`, `git branch -D main` → the target
///   branch is evaluated against `protected_branches`;
/// - `kubectl --context prod-eu ...` / `--context=...`, `helm --kube-context`,
///   `--kubeconfig <file>` and an inline `KUBECONFIG=<file>` prefix decide the
///   k8s context;
/// - inline env assignments (`NODE_ENV=production cmd`) count as env signals;
/// - a `sudo`/`doas` prefix counts as root.
///
/// The k8s context is only probed when the command mentions a k8s tool.
pub fn detect_for_command(
    env: &dyn Environment,
    config: &ContextConfig,
    command: &str,
) -> RuntimeContext {
    detect_inner(env, config, Some(command))
}

fn detect_inner(
    env: &dyn Environment,
    config: &ContextConfig,
    command: Option<&str>,
) -> RuntimeContext {
    let Some(command) = command else {
        // Without a command (status) every signal is probed and the current
        // branch always counts.
        let seg = SegmentTargets {
            mentions_k8s: true,
            git_uses_current: true,
            ..SegmentTargets::default()
        };
        let mut probes = Probes::default();
        let mut ctx = segment_context(env, config, &seg, &mut probes);
        ctx.git_ignore_current_branch = false;
        ctx.refresh(config);
        return ctx;
    };
    let contexts = command_contexts(env, config, command);
    contexts.full(config)
}

/// The context of every simple command of a line (see
/// [`command_contexts`]).
#[derive(Debug, Clone, Default)]
pub struct CommandContexts {
    /// Each simple command with the context it runs in.
    pub parts: Vec<(SegmentTargets, RuntimeContext)>,
    /// `context.sensitive_paths` hit by the line.
    pub sensitive_paths: Vec<String>,
}

impl CommandContexts {
    /// The context of the whole line: for every signal, the most severe value
    /// any of its commands runs with.
    #[must_use]
    pub fn full(&self, config: &ContextConfig) -> RuntimeContext {
        let parts: Vec<&RuntimeContext> = self.parts.iter().map(|(_, c)| c).collect();
        let mut ctx = merge_contexts(&parts, config);
        ctx.sensitive_paths.clone_from(&self.sensitive_paths);
        ctx.refresh(config);
        ctx
    }

    /// The context relevant to the risky commands of the line.
    ///
    /// `groups_of(text)` returns the check groups that matched one command
    /// (its [`SegmentTargets::text`]). Each command's context is filtered to
    /// the groups that matched *that* command (a pod payload always keeps
    /// the k8s signals), and the most severe values are merged. When no
    /// single command matched (a match on the whole line only), every
    /// command counts, filtered by `all_groups`.
    #[must_use]
    pub fn relevant(
        &self,
        config: &ContextConfig,
        groups_of: &dyn Fn(&str) -> std::collections::HashSet<String>,
        all_groups: &std::collections::HashSet<&str>,
    ) -> RuntimeContext {
        let mut filtered: Vec<RuntimeContext> = Vec::new();
        for (seg, ctx) in &self.parts {
            let mut groups = groups_of(&seg.text);
            if groups.is_empty() {
                continue;
            }
            // A k8s tool acts on its cluster whatever group its check is in
            // (`velero backup delete` is a `terraform:` check).
            if seg.place == Place::Pod || seg.mentions_k8s {
                groups.insert("kubernetes".to_string());
            }
            let set: std::collections::HashSet<&str> = groups.iter().map(String::as_str).collect();
            filtered.push(ctx.filter_for_groups(&set, config));
        }
        if filtered.is_empty() {
            for (seg, ctx) in &self.parts {
                let mut set = all_groups.clone();
                if seg.place == Place::Pod {
                    set.insert("kubernetes");
                }
                filtered.push(ctx.filter_for_groups(&set, config));
            }
        }
        let refs: Vec<&RuntimeContext> = filtered.iter().collect();
        let mut ctx = merge_contexts(&refs, config);
        ctx.sensitive_paths.clone_from(&self.sensitive_paths);
        ctx.refresh(config);
        ctx
    }
}

/// Detect the context of every simple command of `command`, in order.
///
/// Each one is judged with the switches made *before* it (`kubectx`,
/// `git checkout`, `export`, `terraform workspace select`, …), never with a
/// switch that comes after it.
#[must_use]
pub fn command_contexts(
    env: &dyn Environment,
    config: &ContextConfig,
    command: &str,
) -> CommandContexts {
    let targets = parse_command_targets(command);
    let mut segments = targets.segments;

    // A git command reached only through the parser's normalization (an
    // alias expansion, `$(which git)`, ...) still acts on the current branch.
    let parsed = crate::parser::parse(command);
    if targets.git_invocations == 0 {
        for s in &parsed.segments {
            if s.starts_with("git ") && parsed.remote_segments.binary_search(s).is_err() {
                let args: Vec<String> = s
                    .split(' ')
                    .skip(1)
                    .filter(|w| !w.is_empty())
                    .map(crate::parser::desentinel)
                    .collect();
                let mut seg = SegmentTargets {
                    text: crate::parser::desentinel(s),
                    ..SegmentTargets::default()
                };
                parse_git(&args, &mut seg, &mut LineState::default());
                segments.push(seg);
            }
        }
    }
    if segments.is_empty() {
        segments.push(SegmentTargets {
            text: command.to_string(),
            ..SegmentTargets::default()
        });
    }

    let mut probes = Probes::default();
    let parts = segments
        .into_iter()
        .map(|seg| {
            let ctx = segment_context(env, config, &seg, &mut probes);
            (seg, ctx)
        })
        .collect::<Vec<_>>();
    debug!("command contexts: {parts:?}");
    CommandContexts {
        parts,
        sensitive_paths: sensitive_path_hits(env, &config.sensitive_paths, &parsed),
    }
}

/// Cached results of the external probes (git, kubectl, kubeconfig files),
/// so a line with several commands probes each only once.
#[derive(Default)]
struct Probes {
    git: Option<(Option<String>, bool)>,
    k8s_ambient: Option<K8sProbe>,
    k8s_by_kubeconfig: std::collections::HashMap<String, K8sProbe>,
}

/// `(context, unknown, not_checked)`.
type K8sProbe = (Option<String>, bool, bool);

impl Probes {
    fn git(&mut self, env: &dyn Environment) -> (Option<String>, bool) {
        self.git
            .get_or_insert_with(|| detect_git_branch(env))
            .clone()
    }

    fn k8s(&mut self, env: &dyn Environment, kubeconfig: Option<&str>) -> K8sProbe {
        match kubeconfig {
            Some(kc) => self
                .k8s_by_kubeconfig
                .entry(kc.to_string())
                .or_insert_with(|| detect_k8s_from_kubeconfig(env, kc))
                .clone(),
            None => self
                .k8s_ambient
                .get_or_insert_with(|| detect_k8s_ambient(env))
                .clone(),
        }
    }
}

/// The context one simple command runs in.
#[allow(clippy::too_many_lines)]
fn segment_context(
    env: &dyn Environment,
    config: &ContextConfig,
    seg: &SegmentTargets,
    probes: &mut Probes,
) -> RuntimeContext {
    let local = seg.place == Place::Local;
    // A value set by the line wins; the process environment only counts for
    // commands that run here.
    let lookup = |key: &str| -> Option<String> {
        match seg.line_var(key) {
            Some(v) => v,
            None if local => env.var(key).filter(|v| !v.is_empty()),
            None => None,
        }
    };
    let first_of = |keys: &[&str]| keys.iter().find_map(|k| lookup(k));

    let euid_root = env.effective_uid() == Some(0);
    let mut ctx = RuntimeContext {
        is_ssh: ["SSH_CONNECTION", "SSH_TTY", "SSH_CLIENT"]
            .iter()
            .any(|k| env_var_non_empty(env, k)),
        is_root: euid_root || seg.sudo_root,
        root_via_sudo: !euid_root && seg.sudo_root,
        root_via: (!euid_root && seg.sudo_root)
            .then(|| seg.root_tool.clone())
            .flatten(),
        ..RuntimeContext::default()
    };

    // Git branch: switched to earlier in the line, or checked out (only
    // meaningful for a command that runs here).
    if let Some(ref b) = seg.git_branch_switch {
        ctx.git_branch = Some(b.clone());
        ctx.git_branch_switched = true;
        // The checkout may have failed (`git checkout typo; git push -f`):
        // the branch checked out before it may still be the current one.
        let applies = !seg.git_fallbacks.is_empty()
            && (seg.git_fallbacks_always || !(seg.git_switch_creates || branch_exists(env, b)));
        if applies && !branch_matches_any(b, &config.protected_branches) {
            for alt in &seg.git_fallbacks {
                let candidate = match alt {
                    CtxAlt::Named(n) => Some(n.clone()),
                    CtxAlt::Current if local => probes.git(env).0,
                    _ => None,
                };
                if let Some(c) = candidate {
                    if branch_matches_any(&c, &config.protected_branches) {
                        ctx.git_branch_switched = matches!(alt, CtxAlt::Named(_));
                        ctx.git_branch = Some(c);
                        break;
                    }
                }
            }
        }
    } else if let Some(dir) = seg.git_dir.as_deref().filter(|_| local) {
        // `git -C ../infra reset --hard …`, `cd repo && git push -f`: the
        // branch checked out there (read from its `.git/HEAD`).
        let base = env.current_dir().unwrap_or_default();
        let path = expand_home(env, dir);
        let path = if path.is_absolute() {
            path
        } else {
            base.join(path)
        };
        let at = crate::agent::CwdEnvironment::new(env, path);
        match read_git_head(&at) {
            GitHead::Branch(b) => ctx.git_branch = Some(b),
            GitHead::Unreadable => ctx.git_unknown = seg.git_uses_current,
            GitHead::NotFound => {}
        }
    } else if local {
        let (branch, unknown) = probes.git(env);
        ctx.git_branch = branch;
        ctx.git_unknown = unknown && seg.git_uses_current;
    }
    ctx.git_targets.clone_from(&seg.git_targets);
    if seg.git_target_unknown && local {
        // An unknown push target may be a protected branch of this
        // repository: the checked-out one, or a protected name it has. It
        // is reported as unknown, never as a branch it may not be.
        ctx.git_target_unknown = unknown_target_may_be_protected(
            env,
            config,
            ctx.git_branch.clone().or_else(|| probes.git(env).0),
        );
    }
    // `git reset --hard origin/main` when `main` is already there: no
    // commit is dropped, the branch does not move.
    let reset_in_place = local
        && seg.git_dir.is_none()
        && seg.git_branch_switch.is_none()
        && seg
            .git_reset_to
            .as_deref()
            .is_some_and(|r| rev_is_head(env, r));
    ctx.git_ignore_current_branch = !seg.git_uses_current || reset_in_place;
    ctx.git_push_all = seg.git_push_all;

    // Kubernetes context: explicit / switched, else probed (a pod payload
    // runs in the cluster its `kubectl exec` targets).
    if seg.mentions_k8s || seg.place == Place::Pod {
        if let Some(ref c) = seg.k8s_context {
            ctx.k8s_context = Some(c.clone());
        } else if seg.k8s_context_unknown {
            ctx.k8s_unknown = true;
        } else if local || seg.place == Place::Pod {
            let (c, unknown, not_checked) = probes.k8s(env, seg.kubeconfig.as_deref());
            ctx.k8s_context = c;
            ctx.k8s_unknown = unknown;
            ctx.k8s_not_checked = not_checked;
        }
        // The switch may have failed (`kubectx typo; kubectl delete …`), or
        // the context is a variable with several values: the most severe
        // possible context applies.
        // A loop over every context: all of them are possible.
        let all_contexts;
        let seg = if seg.k8s_all_contexts {
            let mut s = seg.clone();
            s.k8s_fallbacks = kubeconfig_contexts(env, seg.kubeconfig.as_deref())
                .into_iter()
                .map(CtxAlt::Named)
                .collect();
            s.k8s_fallbacks.push(CtxAlt::Unknown);
            s.k8s_fallbacks_always = true;
            all_contexts = s;
            &all_contexts
        } else {
            seg
        };
        let known_contexts = kubeconfig_contexts(env, seg.kubeconfig.as_deref());
        let resolvable = seg
            .k8s_context
            .as_deref()
            .is_some_and(|c| known_contexts.iter().any(|k| k == c));
        // `kubectx prdo-eu; kubectl …`: a switch to a context the kubeconfig
        // does not have fails, so the one before it is in effect.
        let failed_switch = !resolvable
            && !known_contexts.is_empty()
            && seg.k8s_context.is_some()
            && !seg.k8s_all_contexts;
        if !seg.k8s_fallbacks.is_empty() && (seg.k8s_fallbacks_always || !resolvable) {
            let prod = |c: &Option<String>| {
                c.as_deref()
                    .is_some_and(|c| matches_any_pattern(c, &config.production_k8s_patterns))
            };
            if !prod(&ctx.k8s_context) {
                let mut unknown = ctx.k8s_unknown;
                for alt in &seg.k8s_fallbacks {
                    let (c, u) = match alt {
                        CtxAlt::Named(n) => (Some(n.clone()), false),
                        CtxAlt::Unknown => (None, true),
                        CtxAlt::Current if local || seg.place == Place::Pod => {
                            let (c, u, _) = probes.k8s(env, seg.kubeconfig.as_deref());
                            (c, u)
                        }
                        CtxAlt::Current => (None, false),
                    };
                    if prod(&c) {
                        // A loop over literal contexts visits this one:
                        // nothing switches (and nothing may fail).
                        ctx.k8s_switch_attempt = if seg.k8s_context_list {
                            None
                        } else {
                            seg.k8s_context.clone()
                        };
                        ctx.k8s_context = c;
                        ctx.k8s_unknown = false;
                        unknown = false;
                        break;
                    }
                    unknown |= u;
                }
                if unknown && !prod(&ctx.k8s_context) {
                    // Production is ruled out, but not which context it is.
                    ctx.k8s_context = None;
                    ctx.k8s_unknown = true;
                } else if failed_switch && !prod(&ctx.k8s_context) {
                    // Label the context still in effect, not the typo.
                    let before = seg.k8s_fallbacks.iter().find_map(|alt| match alt {
                        CtxAlt::Named(n) => Some(n.clone()),
                        CtxAlt::Current if local => probes.k8s(env, seg.kubeconfig.as_deref()).0,
                        _ => None,
                    });
                    if let Some(b) = before {
                        ctx.k8s_switch_attempt.clone_from(&seg.k8s_context);
                        ctx.k8s_context = Some(b);
                    }
                }
            }
        }
    }
    ctx.k8s_namespace.clone_from(&seg.k8s_namespace);

    // Cloud / IaC targets: the command (flags, inline or exported variables
    // earlier in the line) wins over the process environment.
    ctx.aws_profile = seg
        .aws_profile
        .clone()
        .or_else(|| first_of(&["AWS_PROFILE", "AWS_DEFAULT_PROFILE"]));
    ctx.tf_workspace = seg.tf_workspace.clone().or_else(|| lookup("TF_WORKSPACE"));
    // The selected workspace of the working directory (`terraform workspace
    // select` writes it to `.terraform/environment`); read, never run.
    let selected = |env: &dyn Environment| -> Option<String> {
        if !(seg.terraform && local) {
            return None;
        }
        let cwd = env.current_dir().ok()?;
        let base = seg
            .tf_dir
            .as_deref()
            .map_or_else(|| cwd.clone(), |d| expand_home(env, d))
            .components()
            .collect::<PathBuf>();
        let base = if base.is_absolute() {
            base
        } else {
            cwd.join(base)
        };
        let data = lookup("TF_DATA_DIR").unwrap_or_else(|| ".terraform".to_string());
        let file = base.join(data).join("environment");
        env.read_file(&file)
            .ok()
            .map(|w| w.trim().to_string())
            .filter(|w| !w.is_empty() && w != "default")
    };
    if ctx.tf_workspace.is_none() && !seg.tf_dir_unknown {
        ctx.tf_workspace = selected(env);
    }
    let tf_prod = |w: &Option<String>| {
        w.as_deref()
            .is_some_and(|w| matches_any_pattern(w, &config.production_k8s_patterns))
    };
    // `terraform workspace select dev || terraform destroy`, or a typo: the
    // workspace selected before may still be the one in effect.
    if !tf_prod(&ctx.tf_workspace) {
        for alt in &seg.tf_fallbacks {
            let w = match alt {
                CtxAlt::Named(n) => Some(n.clone()),
                CtxAlt::Current => selected(env).or_else(|| lookup("TF_WORKSPACE")),
                CtxAlt::Unknown => None,
            };
            if tf_prod(&w) {
                ctx.tf_workspace = w;
                break;
            }
        }
    }
    if !ctx
        .tf_workspace
        .as_deref()
        .is_some_and(|w| matches_any_pattern(w, &config.production_k8s_patterns))
    {
        if let Some(h) = seg
            .tf_dir_hints
            .iter()
            .find(|h| matches_any_pattern(h, &config.production_k8s_patterns))
        {
            ctx.tf_workspace = Some(h.clone());
        }
    }
    ctx.tf_unknown = seg.tf_dir_unknown && ctx.tf_workspace.is_none();
    ctx.gcp_project = seg.gcp_project.clone().or_else(|| {
        first_of(&[
            "CLOUDSDK_CORE_PROJECT",
            "GOOGLE_CLOUD_PROJECT",
            "GOOGLE_PROJECT",
        ])
    });
    ctx.azure_subscription = seg
        .azure_subscription
        .clone()
        .or_else(|| first_of(&["ARM_SUBSCRIPTION_ID", "AZURE_SUBSCRIPTION_ID"]));
    ctx.cluster.clone_from(&seg.cluster);
    if let Place::Host(ref h) = seg.place {
        ctx.remote_hosts.push(h.clone());
    }

    // Production environment variables.
    for (key, expected_val) in &config.production_env_vars {
        if let Some(val) = lookup(key) {
            if val.eq_ignore_ascii_case(expected_val) {
                ctx.env_signals.push(format!("{key}={val}"));
            }
        }
    }

    ctx.refresh(config);
    ctx
}

/// Merge the contexts of several commands: every signal takes the most
/// severe value any of them has (a production value over an unknown one
/// over any other).
fn merge_contexts(parts: &[&RuntimeContext], config: &ContextConfig) -> RuntimeContext {
    let prod = |v: &Option<String>| {
        v.as_deref()
            .is_some_and(|v| matches_any_pattern(v, &config.production_k8s_patterns))
    };
    let pick = |f: &dyn Fn(&RuntimeContext) -> &Option<String>| -> Option<String> {
        parts
            .iter()
            .map(|p| f(p))
            .find(|v| prod(v))
            .or_else(|| parts.iter().map(|p| f(p)).find(|v| v.is_some()))
            .cloned()
            .flatten()
    };
    let mut out = RuntimeContext {
        is_ssh: parts.iter().any(|p| p.is_ssh),
        is_root: parts.iter().any(|p| p.is_root),
        ..RuntimeContext::default()
    };
    out.root_via_sudo = out.is_root && parts.iter().all(|p| !p.is_root || p.root_via_sudo);
    out.root_via = parts
        .iter()
        .find_map(|p| p.root_via.clone())
        .filter(|_| out.root_via_sudo);
    if let Some(p) = parts.iter().find(|p| prod(&p.k8s_context)) {
        out.k8s_switch_attempt.clone_from(&p.k8s_switch_attempt);
    }

    // Git: the branch of a command that acts on it, protected first.
    let uses: Vec<&&RuntimeContext> = parts
        .iter()
        .filter(|p| !p.git_ignore_current_branch && p.git_branch.is_some())
        .collect();
    let chosen = uses
        .iter()
        .find(|p| {
            p.git_branch
                .as_deref()
                .is_some_and(|b| branch_matches_any(b, &config.protected_branches))
        })
        .or_else(|| uses.first())
        .map(|p| **p)
        .or_else(|| parts.iter().find(|p| p.git_branch.is_some()).copied());
    if let Some(c) = chosen {
        out.git_branch.clone_from(&c.git_branch);
        out.git_branch_switched = c.git_branch_switched;
    }
    out.git_unknown = out.git_branch.is_none() && parts.iter().any(|p| p.git_unknown);
    for p in parts {
        for t in &p.git_targets {
            if !out.git_targets.contains(t) {
                out.git_targets.push(t.clone());
            }
        }
        for h in &p.remote_hosts {
            if !out.remote_hosts.contains(h) {
                out.remote_hosts.push(h.clone());
            }
        }
        for s in &p.env_signals {
            if !out.env_signals.contains(s) {
                out.env_signals.push(s.clone());
            }
        }
    }
    out.git_ignore_current_branch = parts.iter().all(|p| p.git_ignore_current_branch);
    out.git_push_all = parts.iter().any(|p| p.git_push_all);
    out.git_target_unknown = parts.iter().any(|p| p.git_target_unknown);

    // k8s: production, else unknown, else whatever is known.
    if let Some(p) = parts.iter().find(|p| prod(&p.k8s_context)) {
        out.k8s_context.clone_from(&p.k8s_context);
    } else if parts.iter().any(|p| p.k8s_unknown) {
        out.k8s_unknown = true;
    } else {
        out.k8s_context = parts.iter().find_map(|p| p.k8s_context.clone());
    }
    out.k8s_not_checked =
        out.k8s_context.is_none() && !out.k8s_unknown && parts.iter().any(|p| p.k8s_not_checked);
    out.k8s_namespace = pick(&|p| &p.k8s_namespace);
    out.aws_profile = pick(&|p| &p.aws_profile);
    out.tf_workspace = pick(&|p| &p.tf_workspace);
    out.tf_unknown = out.tf_workspace.is_none() && parts.iter().any(|p| p.tf_unknown);
    out.gcp_project = pick(&|p| &p.gcp_project);
    out.azure_subscription = pick(&|p| &p.azure_subscription);
    out.cluster = pick(&|p| &p.cluster);
    out.refresh(config);
    out
}

fn env_var_non_empty(env: &dyn Environment, key: &str) -> bool {
    env.var(key).is_some_and(|v| !v.trim().is_empty())
}

/// What reading the git `HEAD` file directly found.
enum GitHead {
    /// The checked-out branch (`HEAD` for a detached head).
    Branch(String),
    /// A repository was found but its `HEAD` could not be interpreted.
    Unreadable,
    /// No `.git` above the working directory (or `GIT_DIR` is set).
    NotFound,
}

/// Read the checked-out branch from `.git/HEAD` (or the `gitdir:` file of a
/// worktree / submodule) without spawning git: fast in big monorepos, and
/// side-effect free.
fn read_git_head(env: &dyn Environment) -> GitHead {
    if env.var("GIT_DIR").is_some_and(|v| !v.is_empty()) {
        return GitHead::NotFound;
    }
    let Ok(cwd) = env.current_dir() else {
        return GitHead::NotFound;
    };
    let head_file = env.find_file_upward(&cwd, ".git/HEAD");
    let git_file = env.find_file_upward(&cwd, ".git");
    // The innermost repository wins.
    let depth = |p: &Option<PathBuf>, extra: usize| {
        p.as_ref()
            .map(|p| p.components().count().saturating_sub(extra))
    };
    let head = match (depth(&head_file, 1), depth(&git_file, 0)) {
        (None, None) => return GitHead::NotFound,
        (Some(h), Some(g)) if g > h => git_file.and_then(|f| gitdir_head(env, &f)),
        (Some(_), _) => head_file,
        (None, Some(_)) => git_file.and_then(|f| gitdir_head(env, &f)),
    };
    let Some(head) = head else {
        return GitHead::Unreadable;
    };
    let Ok(content) = env.read_file(&head) else {
        return GitHead::Unreadable;
    };
    let content = content.trim();
    if let Some(r) = content.strip_prefix("ref:") {
        let r = r.trim();
        return r
            .strip_prefix("refs/heads/")
            .map_or(GitHead::Unreadable, |b| GitHead::Branch(b.to_string()));
    }
    if content.len() >= 40 && content.chars().all(|c| c.is_ascii_hexdigit()) {
        return GitHead::Branch("HEAD".to_string());
    }
    GitHead::Unreadable
}

/// The `HEAD` path of a `.git` *file* (`gitdir: <path>`).
fn gitdir_head(env: &dyn Environment, git_file: &std::path::Path) -> Option<PathBuf> {
    let content = env.read_file(git_file).ok()?;
    let dir = content
        .lines()
        .find_map(|l| l.strip_prefix("gitdir:"))?
        .trim();
    let dir = PathBuf::from(dir);
    let dir = if dir.is_absolute() {
        dir
    } else {
        git_file.parent()?.join(dir)
    };
    Some(dir.join("HEAD"))
}

/// Whether `rev` names the commit `HEAD` is at (`git reset --hard
/// origin/main` right after a fetch on an up-to-date `main`), read from the
/// ref files without running git. `false` when it cannot be told.
fn rev_is_head(env: &dyn Environment, rev: &str) -> bool {
    let Ok(cwd) = env.current_dir() else {
        return false;
    };
    let Some(head) = env.find_file_upward(&cwd, ".git/HEAD") else {
        return false;
    };
    let Some(git_dir) = head.parent() else {
        return false;
    };
    let packed = env
        .read_file(&git_dir.join("packed-refs"))
        .unwrap_or_default();
    let resolve = |name: &str| -> Option<String> {
        if let Ok(c) = env.read_file(&git_dir.join(name)) {
            let c = c.trim();
            return (c.len() >= 40 && c.chars().all(|c| c.is_ascii_hexdigit()))
                .then(|| c.to_string());
        }
        packed.lines().find_map(|l| {
            let (sha, r) = l.split_once(' ')?;
            (r.trim() == name).then(|| sha.to_string())
        })
    };
    let Ok(head_content) = env.read_file(&head) else {
        return false;
    };
    let head_content = head_content.trim();
    let head_sha = head_content
        .strip_prefix("ref:")
        .map_or_else(|| Some(head_content.to_string()), |r| resolve(r.trim()));
    let Some(head_sha) = head_sha.filter(|s| s.len() >= 40) else {
        return false;
    };
    if rev.len() >= 7 && rev.chars().all(|c| c.is_ascii_hexdigit()) {
        return head_sha.starts_with(&rev.to_ascii_lowercase());
    }
    if rev.contains(['~', '^', '@', ':', '$', '`', '{']) || rev.contains("..") {
        return false;
    }
    [
        rev.to_string(),
        format!("refs/heads/{rev}"),
        format!("refs/tags/{rev}"),
        format!("refs/remotes/{rev}"),
    ]
    .iter()
    .filter(|n| n.starts_with("refs/"))
    .find_map(|n| resolve(n))
    .is_some_and(|sha| sha == head_sha)
}

/// Resolve the checked-out branch. Returns `(branch, unknown)`; `unknown`
/// is set when git did not answer in time, so the caller can treat the
/// context as elevated instead of failing open.
fn detect_git_branch(env: &dyn Environment) -> (Option<String>, bool) {
    let head = read_git_head(env);
    if let GitHead::Branch(b) = head {
        return (Some(b), false);
    }
    match env.run_command_outcome(
        "git",
        &["rev-parse", "--abbrev-ref", "HEAD"],
        GIT_TIMEOUT_MS,
    ) {
        CommandOutcome::Output(b) if !b.is_empty() => (Some(b), false),
        CommandOutcome::TimedOut => (None, true),
        // `--no-context`: unknown only when a repository is known to exist.
        CommandOutcome::Skipped => (None, matches!(head, GitHead::Unreadable)),
        _ => (None, false),
    }
}

/// Programs whose path operands are deleted or overwritten.
const WRITE_PROGRAMS: &[&str] = &[
    "rm", "rmdir", "unlink", "shred", "srm", "mv", "cp", "truncate", "tee", "dd", "find", "chmod",
    "chown", "ln", "install", "rsync",
];

/// `context.sensitive_paths` entries that the (non-remote) command deletes,
/// overwrites or redirects into — or deletes a parent directory of.
#[must_use]
#[allow(clippy::too_many_lines)]
pub fn sensitive_path_hits(
    env: &dyn Environment,
    sensitive: &[String],
    parsed: &crate::parser::Parsed,
) -> Vec<String> {
    if sensitive.is_empty() {
        return Vec::new();
    }
    let home = env.home_dir().map(|h| h.display().to_string());
    let cwd = env
        .current_dir()
        .ok()
        .map(|c| c.display().to_string())
        .unwrap_or_default();
    let resolve = |p: &str| -> String {
        let p = crate::parser::desentinel(p);
        let p = p.trim_matches(|c| c == '"' || c == '\'');
        let expanded = match (home.as_deref(), p) {
            (Some(h), "~" | "$HOME" | "${HOME}") => h.to_string(),
            (Some(h), _) if p.starts_with("~/") => format!("{h}/{}", &p[2..]),
            (Some(h), _) if p.starts_with("$HOME/") => format!("{h}/{}", &p[6..]),
            (Some(h), _) if p.starts_with("${HOME}/") => format!("{h}/{}", &p[8..]),
            _ => p.to_string(),
        };
        let abs = if expanded.starts_with('/') {
            expanded
        } else {
            format!("{cwd}/{expanded}")
        };
        crate::parser::normalize_path(&abs)
    };
    let wanted: Vec<(String, String)> = sensitive
        .iter()
        .filter(|s| !s.trim().is_empty())
        .map(|s| (s.clone(), resolve(s.trim())))
        .collect();

    let mut hits: Vec<String> = Vec::new();
    for seg in &parsed.segments {
        if parsed.remote_segments.binary_search(seg).is_ok() {
            continue;
        }
        let words: Vec<&str> = seg.split(' ').filter(|w| !w.is_empty()).collect();
        let Some(prog) = words.first() else { continue };
        let mut targets: Vec<&str> = Vec::new();
        let mut operands: Vec<&str> = Vec::new();
        let mut i = 1;
        while i < words.len() {
            let w = words[i];
            if crate::parser::is_redirect_word(w) {
                if w.contains('>') {
                    if let Some(t) = words.get(i + 1) {
                        targets.push(t);
                    }
                }
                i += 2;
                continue;
            }
            if let Some(of) = w.strip_prefix("of=") {
                if *prog == "dd" {
                    targets.push(of);
                }
            } else if !w.starts_with('-') {
                operands.push(w);
            }
            i += 1;
        }
        let has = |flags: &[&str]| words.iter().any(|w| flags.contains(w));
        if WRITE_PROGRAMS.contains(prog) {
            match *prog {
                // Only the destination is written.
                "cp" | "install" | "rsync" | "ln" => targets.extend(operands.last()),
                // Tightening permissions (`chmod 600 ~/.ssh/id_rsa`,
                // `chmod go-rwx …`) protects the file: not a hit.
                "chmod" if operands.first().is_some_and(|m| is_tightening_mode(m)) => {}
                // The first operand is the mode / owner.
                "chmod" | "chown" => targets.extend(operands.iter().skip(1)),
                "find"
                    if words
                        .iter()
                        .any(|w| *w == "-delete" || w.starts_with("-exec")) =>
                {
                    targets.extend(
                        words[1..]
                            .iter()
                            .take_while(|w| !w.starts_with('-') && **w != "(" && **w != "!"),
                    );
                }
                "find" | "dd" => {}
                _ => targets.extend(operands),
            }
        } else {
            match *prog {
                // `sed -i … FILE…`: the files after the script are rewritten.
                "sed"
                    if words
                        .iter()
                        .any(|w| w.starts_with("-i") || w.starts_with("--in-place")) =>
                {
                    targets.extend(operands.iter().skip(1));
                }
                // `curl -o FILE` / `wget -O FILE` write FILE.
                "curl" | "wget" => {
                    for (k, w) in words.iter().enumerate() {
                        if matches!(*w, "-o" | "--output" | "-O" | "--output-document") {
                            if let Some(f) = words.get(k + 1) {
                                targets.push(f);
                            }
                        }
                    }
                }
                // `tar --remove-files …` / `zip -m …` delete their inputs.
                "tar" if has(&["--remove-files"]) => targets.extend(operands.iter().skip(1)),
                "zip" if has(&["-m", "--move"]) => targets.extend(operands.iter().skip(1)),
                _ => {}
            }
        }
        for t in targets {
            let t = resolve(t);
            // A glob (`rm -rf ~/.ss*`) may match anything that starts with
            // its literal prefix.
            let glob_prefix = t.find(['*', '?', '[']).map(|i| t[..i].to_string());
            for (shown, s) in &wanted {
                let inside = t == *s || t.starts_with(&format!("{s}/"));
                let parent = s.starts_with(&format!("{}/", t.trim_end_matches('/'))) || t == "/";
                let globbed = glob_prefix
                    .as_ref()
                    .is_some_and(|g| s.starts_with(g.as_str()) || g.starts_with(&format!("{s}/")));
                let (inside, parent) = (inside || globbed, parent);
                if (inside || parent) && !hits.contains(shown) {
                    hits.push(shown.clone());
                }
            }
        }
    }
    hits
}

/// Whether a `chmod` mode only removes access for group / others
/// (`600`, `0400`, `700`, `go-rwx`, `o-w`, `u=rw,go=`).
fn is_tightening_mode(mode: &str) -> bool {
    if !mode.is_empty() && mode.chars().all(|c| c.is_ascii_digit()) {
        // At most `0NNN` (no setuid / setgid / sticky), group and other 0.
        let d: Vec<char> = mode.chars().collect();
        if d.len() > 4 || (d.len() == 4 && d[0] != '0') || d.len() < 3 {
            return false;
        }
        return d[d.len() - 2] == '0' && d[d.len() - 1] == '0';
    }
    !mode.is_empty()
        && mode.split(',').all(|part| {
            let who_end = part.find(['-', '=', '+']).unwrap_or(part.len());
            let (who, rest) = part.split_at(who_end);
            let only_go = !who.is_empty() && who.chars().all(|c| c == 'g' || c == 'o');
            (only_go && (rest.starts_with('-') || rest == "="))
                || (who == "u" && rest.starts_with('='))
                || (only_go && rest.starts_with('='))
        })
}

/// Whether at least one file of a colon-separated kubeconfig list exists.
fn any_kubeconfig_exists(env: &dyn Environment, list: &str) -> bool {
    list.split(':')
        .filter(|p| !p.is_empty())
        .any(|p| env.path_exists(&expand_home(env, p)))
}

/// Resolve the k8s context of an explicit kubeconfig (`--kubeconfig x` /
/// `KUBECONFIG=x`). A kubeconfig that does not exist is `unknown` (kubectl
/// would fail or fall back to something we cannot see), never "normal".
fn detect_k8s_from_kubeconfig(env: &dyn Environment, kc: &str) -> K8sProbe {
    if let Some(c) = current_context_from_kubeconfig(env, kc) {
        return (Some(c), false, false);
    }
    if !any_kubeconfig_exists(env, kc) {
        return (None, true, false);
    }
    let first = kc.split(':').next().unwrap_or(kc);
    match env.run_command_outcome(
        "kubectl",
        &["config", "current-context", "--kubeconfig", first],
        K8S_TIMEOUT_MS,
    ) {
        CommandOutcome::Output(c) if !c.is_empty() => (Some(c), false, false),
        CommandOutcome::TimedOut => (None, true, false),
        CommandOutcome::Skipped => (None, false, true),
        _ => (None, false, false),
    }
}

/// Resolve the ambient k8s context (`kubectl config current-context`, or the
/// kubeconfig file when kubectl cannot be asked).
fn detect_k8s_ambient(env: &dyn Environment) -> K8sProbe {
    let kc_env = env.var("KUBECONFIG").filter(|v| !v.is_empty());
    // `KUBECONFIG` pointing at files that do not exist: unknown.
    if let Some(ref kc) = kc_env {
        if current_context_from_kubeconfig(env, kc).is_none() && !any_kubeconfig_exists(env, kc) {
            return (None, true, false);
        }
    }
    match env.run_command_outcome("kubectl", &["config", "current-context"], K8S_TIMEOUT_MS) {
        CommandOutcome::Output(c) if !c.is_empty() => (Some(c), false, false),
        outcome @ (CommandOutcome::TimedOut | CommandOutcome::Skipped) => {
            // Don't fail open: try the kubeconfig file directly, otherwise
            // report the context as unknown (timeout) or "not checked"
            // (`--no-context`).
            let timed_out = outcome == CommandOutcome::TimedOut;
            let from_file = kc_env.map_or_else(
                || {
                    env.home_dir().and_then(|h| {
                        current_context_from_kubeconfig(
                            env,
                            &h.join(".kube").join("config").display().to_string(),
                        )
                    })
                },
                |kc| current_context_from_kubeconfig(env, &kc),
            );
            from_file.map_or((None, timed_out, !timed_out), |c| (Some(c), false, false))
        }
        _ => (None, false, false),
    }
}

/// The context names of the kubeconfig in effect (`--kubeconfig` /
/// `KUBECONFIG`, else `~/.kube/config`). Empty when it cannot be read.
fn kubeconfig_contexts(env: &dyn Environment, kubeconfig: Option<&str>) -> Vec<String> {
    let list = kubeconfig
        .map(str::to_string)
        .or_else(|| env.var("KUBECONFIG").filter(|v| !v.is_empty()))
        .or_else(|| {
            env.home_dir()
                .map(|h| h.join(".kube").join("config").display().to_string())
        })
        .unwrap_or_default();
    let mut out = Vec::new();
    for raw in list.split(':').filter(|p| !p.is_empty()) {
        let Ok(content) = env.read_file(&expand_home(env, raw)) else {
            continue;
        };
        let mut in_contexts = false;
        for line in content.lines() {
            if !line.starts_with([' ', '\t', '-']) && !line.trim().is_empty() {
                in_contexts = line.trim_end() == "contexts:";
                continue;
            }
            if !in_contexts {
                continue;
            }
            let t = line.trim_start().trim_start_matches('-').trim_start();
            if let Some(v) = t.strip_prefix("name:") {
                let v = v
                    .split(" #")
                    .next()
                    .unwrap_or("")
                    .trim()
                    .trim_matches(|c| c == '"' || c == '\'');
                if !v.is_empty() {
                    out.push(v.to_string());
                }
            }
        }
    }
    out
}

/// Whether a local branch named `branch` exists (`.git/refs/heads/…` or
/// `packed-refs`), read without running git.
fn branch_exists(env: &dyn Environment, branch: &str) -> bool {
    let Ok(cwd) = env.current_dir() else {
        return false;
    };
    let Some(head) = env.find_file_upward(&cwd, ".git/HEAD") else {
        return false;
    };
    let Some(git_dir) = head.parent() else {
        return false;
    };
    if env
        .read_file(&git_dir.join("refs").join("heads").join(branch))
        .is_ok()
    {
        return true;
    }
    env.read_file(&git_dir.join("packed-refs")).is_ok_and(|p| {
        p.lines()
            .any(|l| l.split_whitespace().nth(1) == Some(&format!("refs/heads/{branch}")))
    })
}

/// The protected branch a `git push --force-with-lease` of the line pushes to.
///
/// Also `--force-if-includes`. The lease only guards against overwriting
/// unseen remote work: the push still rewrites the branch's shared history.
#[must_use]
pub fn protected_force_with_lease(
    env: &dyn Environment,
    config: &ContextConfig,
    command: &str,
    parsed: &crate::parser::Parsed,
) -> Option<String> {
    let lease = |s: &str| {
        s.contains("push")
            && (s.contains("--force-with-lease") || s.contains("--force-if-includes"))
    };
    if !parsed.segments.iter().any(|s| lease(s)) {
        return None;
    }
    let protected = |b: &String| branch_matches_any(b, &config.protected_branches);
    let targets = parse_command_targets(command);
    for seg in targets
        .segments
        .iter()
        .filter(|s| s.git && s.git_force_lease)
    {
        if let Some(t) = seg.git_targets.iter().find(|t| protected(t)) {
            return Some(t.clone());
        }
        let local = seg.place == Place::Local;
        let current = || match seg.git_branch_switch {
            Some(ref b) => Some(b.clone()),
            None if local => detect_git_branch(env).0,
            None => None,
        };
        if seg.git_uses_current {
            if let Some(b) = current().filter(protected) {
                return Some(b);
            }
        }
        // A target only known when the line runs (`origin $B`, `$(cat
        // f)`, an xargs `{}`) in a repository with a protected branch: it
        // may be one of them. Reported as unknown, not as a branch name.
        if seg.git_target_unknown
            && local
            && unknown_target_may_be_protected(env, config, current())
        {
            return Some(UNKNOWN_PUSH_TARGET.to_string());
        }
    }
    None
}

/// What [`protected_force_with_lease`] returns for a push whose target is
/// only known when the line runs.
pub const UNKNOWN_PUSH_TARGET: &str = "(unknown)";

/// Whether a push target that is only known when the line runs may be a
/// protected branch: the checked-out branch is protected, or the
/// repository has a branch with a protected name.
fn unknown_target_may_be_protected(
    env: &dyn Environment,
    config: &ContextConfig,
    current: Option<String>,
) -> bool {
    current.is_some_and(|b| branch_matches_any(&b, &config.protected_branches))
        || config
            .protected_branches
            .iter()
            .filter(|p| !p.contains(['*', '?', '[']))
            .any(|p| branch_exists(env, p))
}

/// Read `current-context:` from a (colon-separated list of) kubeconfig
/// file(s). The first file that sets a non-empty value wins, matching
/// kubectl's merge rules.
fn current_context_from_kubeconfig(env: &dyn Environment, list: &str) -> Option<String> {
    for raw in list.split(':').filter(|p| !p.is_empty()) {
        let path = expand_home(env, raw);
        let Ok(content) = env.read_file(&path) else {
            continue;
        };
        for line in content.lines() {
            if let Some(rest) = line.strip_prefix("current-context:") {
                let v = rest
                    .split(" #")
                    .next()
                    .unwrap_or("")
                    .trim()
                    .trim_matches(|c| c == '"' || c == '\'');
                if !v.is_empty() {
                    return Some(v.to_string());
                }
            }
        }
    }
    None
}

fn expand_home(env: &dyn Environment, p: &str) -> PathBuf {
    let rest = p
        .strip_prefix("~/")
        .or_else(|| p.strip_prefix("$HOME/"))
        .or_else(|| p.strip_prefix("${HOME}/"));
    match (rest, env.home_dir()) {
        (Some(rest), Some(home)) => home.join(rest),
        _ => PathBuf::from(p),
    }
}

/// Compute the aggregate risk level from context signals.
pub(crate) fn compute_risk_level(ctx: &RuntimeContext, config: &ContextConfig) -> RiskLevel {
    ctx.risk_reasons(config)
        .into_iter()
        .map(|(level, _)| level)
        .max()
        .unwrap_or(RiskLevel::Normal)
}

/// Check if a branch name matches any of the given branch patterns.
/// Supports exact matches and globs (`*`, `?`), e.g. `"release/*"`.
#[must_use]
///
/// Invisible characters (zero-width spaces, bidi controls, ...) are removed
/// before matching, so a branch named `main\u{200b}` is still protected.
pub fn branch_matches_any(branch: &str, patterns: &[String]) -> bool {
    let cleaned = strip_invisible(branch);
    let branch = cleaned.as_str();
    patterns.iter().any(|pattern| {
        if pattern.contains('*') || pattern.contains('?') {
            glob_match(pattern.as_bytes(), branch.as_bytes())
        } else {
            branch == pattern
        }
    })
}

/// Check whether a k8s context name matches any production pattern.
///
/// See the module docs: segment-boundary matching, case-insensitive; a
/// pattern containing `*`/`?` is a glob over the whole name.
#[must_use]
pub fn matches_any_pattern(value: &str, patterns: &[String]) -> bool {
    let lower = strip_invisible(value).to_ascii_lowercase();
    let segments = split_segments(&lower);
    patterns.iter().any(|p| {
        let p = p.to_ascii_lowercase();
        if p.contains('*') || p.contains('?') {
            return glob_match(p.as_bytes(), lower.as_bytes());
        }
        let needle = split_segments(&p);
        !needle.is_empty()
            && segments
                .windows(needle.len())
                .any(|w| w == needle.as_slice())
    })
}

/// Whether `c` is invisible when printed: zero-width characters, bidi
/// controls, the BOM, soft hyphen and other format characters.
#[must_use]
pub const fn is_invisible(c: char) -> bool {
    matches!(
        c,
        '\u{00ad}'
            | '\u{034f}'
            | '\u{061c}'
            | '\u{115f}'
            | '\u{1160}'
            | '\u{17b4}'
            | '\u{17b5}'
            | '\u{180e}'
            | '\u{200b}'..='\u{200f}'
            | '\u{202a}'..='\u{202e}'
            | '\u{2060}'..='\u{2064}'
            | '\u{2066}'..='\u{206f}'
            | '\u{3164}'
            | '\u{feff}'
            | '\u{ffa0}'
            | '\u{fe00}'..='\u{fe0f}'
    )
}

/// Remove invisible characters (see [`is_invisible`]).
#[must_use]
pub fn strip_invisible(s: &str) -> String {
    s.chars().filter(|c| !is_invisible(*c)).collect()
}

/// Escape invisible and control characters for display, so `main\u{200b}`
/// does not look like `main`: each one is shown as `\u{XXXX}` (control
/// characters other than tab/newline too).
#[must_use]
pub fn escape_invisible(s: &str) -> String {
    use std::fmt::Write as _;
    if !s
        .chars()
        .any(|c| is_invisible(c) || (c.is_control() && c != '\t' && c != '\n'))
    {
        return s.to_string();
    }
    let mut out = String::with_capacity(s.len() + 8);
    for c in s.chars() {
        if is_invisible(c) || (c.is_control() && c != '\t' && c != '\n') {
            let _ = write!(out, "\\u{{{:x}}}", c as u32);
        } else {
            out.push(c);
        }
    }
    out
}

/// Whether `c` is a joiner or variation selector that text needs.
///
/// U+200C (zero-width non-joiner, Persian spelling), U+200D (zero-width
/// joiner, Indic conjuncts and emoji sequences such as 👩‍💻) and U+FE0E /
/// U+FE0F (text / emoji presentation, 🏳️‍🌈).
#[must_use]
pub const fn is_text_joiner(c: char) -> bool {
    matches!(c, '\u{200c}' | '\u{200d}' | '\u{fe0e}' | '\u{fe0f}')
}

/// [`escape_invisible`] for free text (check descriptions, alternatives).
///
/// The joiners and variation selectors of [`is_text_joiner`] are kept as
/// characters, as the challenge banner and JSON output keep them. Bidi
/// controls, other zero-width characters and control characters are still
/// shown as `\u{XXXX}`. Ids, paths and branch names use
/// [`escape_invisible`], where a joiner could disguise a name.
#[must_use]
pub fn escape_invisible_text(s: &str) -> String {
    use std::fmt::Write as _;
    let escaped = |c: char| {
        !is_text_joiner(c) && (is_invisible(c) || (c.is_control() && c != '\t' && c != '\n'))
    };
    if !s.chars().any(escaped) {
        return s.to_string();
    }
    let mut out = String::with_capacity(s.len() + 8);
    for c in s.chars() {
        if escaped(c) {
            let _ = write!(out, "\\u{{{:x}}}", c as u32);
        } else {
            out.push(c);
        }
    }
    out
}

fn split_segments(s: &str) -> Vec<&str> {
    s.split(|c: char| !c.is_ascii_alphanumeric())
        .filter(|seg| !seg.is_empty())
        .collect()
}

/// Minimal glob matcher supporting `*` (any run) and `?` (one byte).
const fn glob_match(pattern: &[u8], text: &[u8]) -> bool {
    let (mut p, mut t) = (0usize, 0usize);
    let (mut star, mut mark) = (None::<usize>, 0usize);
    while t < text.len() {
        if p < pattern.len() && (pattern[p] == b'?' || pattern[p] == text[t]) {
            p += 1;
            t += 1;
        } else if p < pattern.len() && pattern[p] == b'*' {
            star = Some(p);
            mark = t;
            p += 1;
        } else if let Some(s) = star {
            p = s + 1;
            mark += 1;
            t = mark;
        } else {
            return false;
        }
    }
    while p < pattern.len() && pattern[p] == b'*' {
        p += 1;
    }
    p == pattern.len()
}

/// Given a base challenge level and a risk level, return the escalated
/// challenge. Escalation can only make things **stricter**, never weaker.
#[must_use]
pub fn escalate_challenge(
    base: &Challenge,
    risk_level: RiskLevel,
    escalation: &EscalationConfig,
) -> Challenge {
    let context_min = match risk_level {
        RiskLevel::Normal => return *base,
        RiskLevel::Elevated => &escalation.elevated,
        RiskLevel::Critical => &escalation.critical,
    };

    // Return the stricter of the two
    base.stricter(*context_min)
}

// ---------------------------------------------------------------------------
// Effective challenge (all escalation layers) with reasons
// ---------------------------------------------------------------------------

/// The challenge that will actually be asked, and why.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EffectiveChallenge {
    /// The user's configured challenge for this mode.
    pub base: Challenge,
    /// The final challenge after every escalation layer.
    pub challenge: Challenge,
    /// Why the challenge is stricter than `base` (empty when it is not).
    pub reasons: Vec<String>,
}

impl EffectiveChallenge {
    /// `true` only when the challenge is strictly stronger than the base.
    #[must_use]
    pub fn is_escalated(&self) -> bool {
        self.challenge.is_stricter_than(self.base)
    }

    /// A one-line explanation, e.g.
    /// "Escalated to Yes (from Math): protected branch `main`, SSH session".
    /// `None` unless the challenge actually got stricter.
    #[must_use]
    pub fn note(&self) -> Option<String> {
        if !self.is_escalated() {
            return None;
        }
        let mut s = format!("Escalated to {} (from {})", self.challenge, self.base);
        if !self.reasons.is_empty() {
            s.push_str(": ");
            s.push_str(&self.reasons.join(", "));
        }
        Some(s)
    }
}

/// Compute the effective challenge by applying every escalation layer in
/// order. Each layer is a floor, so the result can only be stricter than
/// the base (`Enter < Math < Yes`):
///
/// 1. **Base** — `resolved.challenge`
/// 2. **Severity** — `severity_escalation` (Critical→Yes, High→Math by default)
/// 3. **Group** — `group_escalation[check.from]`
/// 4. **Check-ID** — `check_escalation[check.id]`
/// 5. **Context** — `escalate_challenge(risk_level)` (SSH→Math, root/prod→Yes)
/// 6. **Policy** — `.shellfirm.yaml` challenge overrides
///
/// Reasons are reported for the layers whose floor is what made the final
/// challenge stricter than the base.
#[must_use]
pub fn effective_challenge(
    settings: &Settings,
    resolved: &ResolvedSettings,
    checks: &[&Check],
    context: &RuntimeContext,
    merged_policy: &MergedPolicy,
) -> EffectiveChallenge {
    let base = resolved.challenge;
    let mut floors: Vec<(Challenge, String)> = Vec::new();

    // Layer 2: severity (highest severity across all matched checks)
    if let Some(sev) = checks.iter().map(|c| c.severity).max() {
        if let Some(floor) = resolved.severity_escalation.challenge_for_severity(sev) {
            floors.push((floor, format!("severity {sev}")));
        }
    }

    // Layer 3: group escalation
    for check in checks {
        if let Some(&floor) = settings.group_escalation.get(&check.from) {
            floors.push((floor, format!("`{}` group escalation", check.from)));
        }
    }

    // Layer 4: check-ID escalation
    for check in checks {
        if let Some(&floor) = settings.check_escalation.get(&check.id) {
            floors.push((floor, format!("`{}` check escalation", check.id)));
        }
    }

    // Layer 5: context escalation. When a policy file's `context` has an
    // effect, the reason is credited to it, with the same text whether the
    // command runs inside the repository or is aimed at it from outside
    // (`git -C DIR`, `cd DIR && …`, a path argument; layer 6).
    let policy_label = merged_policy.sources_label();
    let credited = |reason: String| match &policy_label {
        Some(label) => format!("{reason} ({label})"),
        None => reason,
    };
    let context_floor = escalate_challenge(&base, context.risk_level, &settings.context.escalation);
    if context.risk_level != RiskLevel::Normal {
        for (level, reason) in context.risk_reasons(&settings.context) {
            if level == context.risk_level {
                floors.push((context_floor, credited(reason)));
            }
        }
    }

    // Layer 6: project policy overrides. A policy is credited "for `<id>`"
    // only when it has a rule for that id; a floor that only comes from a
    // target repository's `context:` is reported as the
    // context risk, labelled with the policy it came from.
    for check in checks {
        if let Some(&floor) = merged_policy.challenge_overrides.get(&check.id) {
            if let Some(label) = merged_policy.rule_label_for(&check.id) {
                floors.push((floor, format!("{label} for `{}`", check.id)));
                continue;
            }
            let label = policy_label
                .clone()
                .unwrap_or_else(|| "project policy (.shellfirm.yaml)".to_string());
            let context_reasons: Vec<String> = context
                .risk_reasons(&settings.context)
                .into_iter()
                .filter(|(level, _)| *level == context.risk_level)
                .map(|(_, reason)| format!("{reason} ({label})"))
                .collect();
            if context_reasons.is_empty() {
                floors.push((floor, format!("context risk ({label})")));
            }
            for reason in context_reasons {
                floors.push((floor, reason));
            }
        }
    }

    let challenge = floors.iter().fold(base, |acc, (f, _)| acc.stricter(*f));

    let mut reasons: Vec<String> = Vec::new();
    if challenge.is_stricter_than(base) {
        for (floor, reason) in floors {
            if floor == challenge && !reasons.contains(&reason) {
                reasons.push(reason);
            }
        }
    }
    // "protected branch `develop`" and "protected branch `develop` (project
    // policy …)" are one reason: keep the labelled one.
    let labelled: Vec<String> = reasons.clone();
    reasons.retain(|r| {
        !labelled.iter().any(|l| {
            l.strip_prefix(r.as_str())
                .is_some_and(|rest| rest.starts_with(" ("))
        })
    });

    EffectiveChallenge {
        base,
        challenge,
        reasons,
    }
}

/// Why a set of matched checks is denied outright (empty when it is not).
#[must_use]
pub fn deny_reasons(
    settings: &Settings,
    checks: &[&Check],
    merged_policy: &MergedPolicy,
) -> Vec<String> {
    let mut reasons = Vec::new();
    for check in checks {
        if settings.deny_patterns_ids.contains(&check.id) {
            reasons.push(format!("`{}` is on your deny list", check.id));
        } else if merged_policy.is_denied(&check.id) {
            reasons.push(format!(
                "`{}` is denied by the {}",
                check.id,
                merged_policy
                    .label_for(&check.id)
                    .unwrap_or_else(|| "project policy (.shellfirm.yaml)".to_string())
            ));
        }
    }
    reasons.dedup();
    reasons
}

// ---------------------------------------------------------------------------
// Command target parsing
// ---------------------------------------------------------------------------

/// Where a simple command of the line runs.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub enum Place {
    /// On this machine, in this shell.
    #[default]
    Local,
    /// The payload of `ssh host …`: on another host. Local state (checked-out
    /// branch, current kube context, process environment) says nothing about
    /// it; only signals written in the payload itself count.
    Host(String),
    /// The payload of `docker|podman exec …`: inside a container.
    Container,
    /// The payload of `kubectl exec … -- CMD`: inside a pod of the cluster the
    /// `kubectl` invocation targets. The k8s context still applies; local
    /// paths, branch and environment do not.
    Pod,
}

/// What one simple command of a line targets.
///
/// The switches made by earlier commands of the same line are applied (`kubectx prod; …`,
/// `git checkout main && …`, `export NODE_ENV=production; …`). A switch only
/// affects the commands *after* it.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
#[allow(clippy::struct_excessive_bools)]
pub struct SegmentTargets {
    /// The command re-joined as shell text (used to find which commands of
    /// the line matched a check).
    pub text: String,
    /// Where the command runs.
    pub place: Place,
    /// Runs as root through `sudo`/`doas`/`su`/`pkexec`/`runuser`.
    pub sudo_root: bool,
    /// The wrapper behind [`Self::sudo_root`].
    pub root_tool: Option<String>,
    /// A `terraform` / `tofu` / `terragrunt` invocation (its workspace is
    /// read from the data directory when no switch names it).
    pub terraform: bool,
    /// Other terraform workspaces the command may run in: an earlier
    /// `workspace select` may have failed.
    pub tf_fallbacks: Vec<CtxAlt>,
    /// The directory a terraform command works in (`-chdir=DIR`, or a `cd`
    /// earlier in the line).
    pub tf_dir: Option<String>,
    /// The terraform directory is a run-time value (`-chdir=$ENV`).
    pub tf_dir_unknown: bool,
    /// A cluster deleted / changed by name (see [`RuntimeContext::cluster`]).
    pub cluster: Option<String>,
    /// The directory a git command acts in when it is not the current one
    /// (`git -C repo …`, `cd repo && git …`): its checked-out branch counts.
    pub git_dir: Option<String>,
    /// The directory an `env -C DIR` / `env --chdir=DIR` wrapper runs the
    /// command in (relative to the line's directory, as written).
    pub chdir: Option<String>,
    /// A `git` invocation.
    pub git: bool,
    /// The git invocation acts on the checked-out branch.
    pub git_uses_current: bool,
    /// A push target is only known when the line runs (`git push -f origin
    /// "$B"`, an xargs `{}`): it may be any branch, a protected one too.
    pub git_target_unknown: bool,
    /// `git push --force-with-lease` / `--force-if-includes` (without a
    /// plain `-f` / `--force`, those are `git:force_push`).
    pub git_force_lease: bool,
    /// The commit a `git reset <rev>` moves the branch to (as written).
    pub git_reset_to: Option<String>,
    /// Branches the git invocation targets explicitly.
    pub git_targets: Vec<String>,
    /// `git push --all` / `--mirror`.
    pub git_push_all: bool,
    /// The branch an earlier `git checkout|switch B` of the line switched to.
    pub git_branch_switch: Option<String>,
    /// The command is a k8s tool (kubectl, helm, …).
    pub mentions_k8s: bool,
    /// The command only switches context (`kubectx`, `use-context`,
    /// `kubens`, …): nothing else runs.
    pub switch_only: bool,
    /// k8s context: `--context` / `--kube-context`, or switched earlier.
    pub k8s_context: Option<String>,
    /// The k8s context was switched to an unknown value (`kubectx -`).
    pub k8s_context_unknown: bool,
    /// `--kubeconfig` / `KUBECONFIG=` in effect.
    pub kubeconfig: Option<String>,
    /// `-n` / `--namespace`, or `kubens` earlier.
    pub k8s_namespace: Option<String>,
    /// `aws --profile`.
    pub aws_profile: Option<String>,
    /// `terraform workspace select` earlier in the line.
    pub tf_workspace: Option<String>,
    /// `gcloud --project`, positional project, or `gcloud config set project`.
    pub gcp_project: Option<String>,
    /// `az --subscription`, or `az account set` earlier.
    pub azure_subscription: Option<String>,
    /// Variables set (`Some`) or unset (`None`) by the line for this command:
    /// earlier `export`/`unset` plus inline `NAME=value` assignments.
    pub env: Vec<(String, Option<String>)>,
    /// Other k8s contexts the command may run in: a switch earlier in the
    /// line may have failed (`kubectx typo; kubectl delete …`), or the
    /// `--context` is a variable with several values. The most severe one
    /// applies.
    pub k8s_fallbacks: Vec<CtxAlt>,
    /// The fallbacks apply even when `k8s_context` names a context of the
    /// kubeconfig (the switch was not joined to this command with `&&`).
    pub k8s_fallbacks_always: bool,
    /// `--context $c` takes several values (`for c in dev prod-eu`): the
    /// fallbacks are the other values, not a switch that may fail.
    pub k8s_context_list: bool,
    /// The command runs once per context of the kubeconfig (a loop over
    /// `kubectl config get-contexts`): every context counts.
    pub k8s_all_contexts: bool,
    /// Like `k8s_fallbacks`, for the branch an earlier checkout switched to.
    pub git_fallbacks: Vec<CtxAlt>,
    /// Like `k8s_fallbacks_always`.
    pub git_fallbacks_always: bool,
    /// The earlier checkout creates the branch (`-b` / `-c`).
    pub git_switch_creates: bool,
    /// Directory / var-file names of a terraform command (`-chdir=envs/prod`,
    /// `-var-file=prod.tfvars`, `cd envs/prod && …`): a production name
    /// there counts like a production workspace.
    pub tf_dir_hints: Vec<String>,
}

impl SegmentTargets {
    /// The value of `key` set by the line (`Some(None)` = unset).
    #[allow(clippy::option_option)]
    fn line_var(&self, key: &str) -> Option<Option<String>> {
        self.env
            .iter()
            .rev()
            .find(|(k, _)| k == key)
            .map(|(_, v)| v.clone().filter(|v| !v.is_empty()))
    }
}

/// What a command line explicitly targets: every simple command
/// ([`Self::segments`], in execution order) plus a few line-wide summaries.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
#[allow(clippy::struct_excessive_bools)]
pub struct CommandTargets {
    /// Number of `git` invocations found.
    pub git_invocations: usize,
    /// At least one git invocation acts on the checked-out branch.
    pub git_uses_current: bool,
    /// Explicit branch targets (all git invocations).
    pub git_targets: Vec<String>,
    /// `git push --all` / `--mirror`.
    pub git_push_all: bool,
    /// The command mentions a k8s tool (kubectl, helm, ...).
    pub mentions_k8s: bool,
    /// k8s context of the first local k8s command that does more than switch
    /// context (used to point blast-radius queries at the right cluster).
    pub k8s_context: Option<String>,
    /// Kubeconfig of that same command.
    pub kubeconfig: Option<String>,
    /// Some local command runs as root (`sudo`, `su -c`, `pkexec`, …).
    pub sudo_root: bool,
    /// Hosts of `ssh host …` invocations.
    pub remote_hosts: Vec<String>,
    /// Every simple command, with the line's earlier switches applied.
    pub segments: Vec<SegmentTargets>,
}

/// Switches made by the commands of a line so far.
#[derive(Debug, Clone, Default)]
#[allow(clippy::struct_excessive_bools)]
struct LineState {
    k8s_context: Option<String>,
    k8s_unknown: bool,
    /// Contexts that were in effect before the last switch.
    k8s_fallbacks: Vec<CtxAlt>,
    /// Every command since the last switch is in an `&&` chain after it.
    k8s_switch_certain: bool,
    k8s_namespace: Option<String>,
    git_branch: Option<String>,
    /// Branches that were checked out before the last switch.
    git_fallbacks: Vec<CtxAlt>,
    git_switch_certain: bool,
    /// The last switch creates the branch (`git checkout -b new`).
    git_switch_creates: bool,
    tf_workspace: Option<String>,
    /// Workspaces selected before the last `workspace select`.
    tf_fallbacks: Vec<CtxAlt>,
    tf_switch_certain: bool,
    gcp_project: Option<String>,
    azure_subscription: Option<String>,
    env: Vec<(String, Option<String>)>,
    /// Shell variables set earlier in the line (`C=prod-eu`, `for c in a b`):
    /// their possible values.
    vars: std::collections::HashMap<String, Vec<String>>,
    /// The directory the line `cd`-ed into (relative to the start).
    cwd: Option<String>,
    /// The line lists the kubeconfig's contexts (`kubectl config
    /// get-contexts`, a bare `kubectx`): a context taken from run-time
    /// output can be any of them.
    lists_contexts: bool,
    /// The literal lines the previous command pipes into this one
    /// (`echo feature/login | xargs -I{} …`).
    pipe_values: Option<Vec<String>>,
}

impl LineState {
    /// The k8s context in effect now, as a fallback value.
    fn k8s_alt(&self) -> CtxAlt {
        if self.k8s_unknown {
            CtxAlt::Unknown
        } else {
            self.k8s_context
                .clone()
                .map_or(CtxAlt::Current, CtxAlt::Named)
        }
    }

    /// The branch checked out now, as a fallback value.
    fn git_alt(&self) -> CtxAlt {
        self.git_branch
            .clone()
            .map_or(CtxAlt::Current, CtxAlt::Named)
    }
}

/// A context value a command may run with when a switch made earlier in the
/// line may have failed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CtxAlt {
    /// The context of the shell before the line (probed).
    Current,
    /// A named context / branch.
    Named(String),
    /// Unknown (`kubectx -`).
    Unknown,
}

/// What a wrapper passes down to the command it runs.
#[derive(Debug, Clone, Default)]
struct Inherit {
    place: Place,
    sudo_root: bool,
    root_tool: Option<String>,
    env: Vec<(String, Option<String>)>,
    /// For [`Place::Pod`]: the k8s target of the `kubectl exec`.
    k8s_context: Option<String>,
    k8s_unknown: bool,
    kubeconfig: Option<String>,
    k8s_namespace: Option<String>,
    /// The other contexts the `kubectl exec` may target (a switch before it
    /// may have failed).
    k8s_fallbacks: Vec<CtxAlt>,
    k8s_fallbacks_always: bool,
}

/// Parse a command line for the things context detection cares about.
#[must_use]
pub fn parse_command_targets(command: &str) -> CommandTargets {
    let mut out = CommandTargets::default();
    let mut state = LineState {
        lists_contexts: lists_kube_contexts(command),
        ..LineState::default()
    };
    parse_into(command, &mut out, &mut state, &Inherit::default(), 0);
    for s in &out.segments {
        if s.git {
            out.git_invocations += 1;
        }
        if s.place == Place::Local {
            out.git_uses_current |= s.git_uses_current;
            out.sudo_root |= s.sudo_root;
        }
        for t in &s.git_targets {
            if !out.git_targets.contains(t) {
                out.git_targets.push(t.clone());
            }
        }
        out.git_push_all |= s.git_push_all;
        out.mentions_k8s |= s.mentions_k8s;
        if let Place::Host(ref h) = s.place {
            if !out.remote_hosts.contains(h) {
                out.remote_hosts.push(h.clone());
            }
        }
    }
    if let Some(s) = out
        .segments
        .iter()
        .find(|s| s.place == Place::Local && s.mentions_k8s && !s.switch_only)
    {
        out.k8s_context.clone_from(&s.k8s_context);
        out.kubeconfig.clone_from(&s.kubeconfig);
    }
    out
}

/// Whether the line enumerates the kubeconfig's contexts
/// (`kubectl config get-contexts`, `kubectx` with no argument in a pipe or
/// substitution).
fn lists_kube_contexts(command: &str) -> bool {
    command.contains("get-contexts")
        || [
            "$(kubectx)",
            "`kubectx`",
            "kubectx |",
            "kubectx|",
            "kubectl config view",
        ]
        .iter()
        .any(|p| command.contains(p))
}

/// Whether a context / namespace value is a literal name, not a run-time
/// placeholder (`$c`, `$(…)`, `{}`, `%`, …).
fn is_literal_name(v: &str) -> bool {
    !v.is_empty()
        && v.chars()
            .all(|c| c.is_alphanumeric() || matches!(c, '-' | '_' | '.' | ':' | '@' | '/'))
}

fn parse_into(
    command: &str,
    out: &mut CommandTargets,
    state: &mut LineState,
    inh: &Inherit,
    depth: usize,
) {
    if depth > 6 {
        return;
    }
    let mut pending_cd_failure: Option<Option<String>> = None;
    for (segment, op) in tokenize_segments_with_ops(command) {
        let before_k8s = state.k8s_alt();
        let before_k8s_fallbacks = state.k8s_fallbacks.clone();
        let before_git = state.git_alt();
        let before_git_fallbacks = state.git_fallbacks.clone();
        let k8s_before = (state.k8s_context.clone(), state.k8s_unknown);
        let git_before = state.git_branch.clone();
        let tf_before = state.tf_workspace.clone();
        let tf_before_fallbacks = state.tf_fallbacks.clone();
        // `cd envs/prod || terraform destroy`: the command after `||` runs
        // only when the `cd` failed, in the directory before it.
        let cd_failed_dir = pending_cd_failure.take();
        let cwd_after_cd = cd_failed_dir
            .as_ref()
            .map(|before| std::mem::replace(&mut state.cwd, before.clone()));
        let cwd_before = state.cwd.clone();
        parse_segment(&segment, out, state, inh, depth);
        state.pipe_values = if op == "|" {
            literal_output_lines(&segment)
        } else {
            None
        };
        if let Some(after) = cwd_after_cd {
            if state.cwd == cwd_before {
                state.cwd = after;
            }
        }
        let is_cd = segment
            .first()
            .is_some_and(|t| matches!(program_name(t), "cd" | "pushd"));
        if is_cd && op == "||" && state.cwd != cwd_before {
            pending_cd_failure = Some(cwd_before.clone());
        }
        if state.tf_workspace != tf_before {
            let mut alts = vec![tf_before.map_or(CtxAlt::Current, CtxAlt::Named)];
            alts.extend(tf_before_fallbacks);
            alts.dedup();
            state.tf_fallbacks = alts;
            state.tf_switch_certain = op == "&&";
        } else if op != "&&" {
            state.tf_switch_certain = false;
        }
        // A switch made by this command: until it is known to have worked,
        // the context before it may still be the one in effect.
        if (state.k8s_context.clone(), state.k8s_unknown) != k8s_before {
            let mut alts = vec![before_k8s];
            alts.extend(before_k8s_fallbacks);
            alts.dedup();
            state.k8s_fallbacks = alts;
            // `kubie ctx X` starts a subshell in X: the commands after it on
            // this line run in the original context once it exits.
            let kubie_subshell = segment.first().is_some_and(|t| program_name(t) == "kubie");
            state.k8s_switch_certain = op == "&&" && !kubie_subshell;
        } else if op != "&&" {
            state.k8s_switch_certain = false;
        }
        if state.git_branch != git_before {
            let mut alts = vec![before_git];
            alts.extend(before_git_fallbacks);
            alts.dedup();
            state.git_fallbacks = alts;
            state.git_switch_certain = op == "&&";
        } else if op != "&&" {
            state.git_switch_certain = false;
        }
    }
}

/// The lines a literal `echo WORDS` / `printf '%s\n' WORDS` prints (what a
/// following `xargs -I{}` reads), if every word is literal.
fn literal_output_lines(segment: &[String]) -> Option<Vec<String>> {
    let (prog, args) = segment.split_first()?;
    let literal = |w: &String| !w.contains(['$', '`', '*', '?']) && !w.contains("{}");
    let lines: Vec<String> = match program_name(prog) {
        "echo" => {
            let args: Vec<&String> = args
                .iter()
                .filter(|a| !matches!(a.as_str(), "-n" | "-e" | "-E"))
                .collect();
            if args.is_empty() || !args.iter().all(|a| literal(a)) {
                return None;
            }
            vec![args
                .iter()
                .map(|a| a.as_str())
                .collect::<Vec<_>>()
                .join(" ")]
        }
        "printf" => {
            let (fmt, rest) = args.split_first()?;
            if !rest.iter().all(literal) {
                return None;
            }
            if rest.is_empty() {
                if !literal(fmt) || fmt.contains('%') {
                    return None;
                }
                fmt.split("\\n").map(str::to_string).collect()
            } else if fmt == "%s\\n" || fmt == "%s" {
                rest.to_vec()
            } else {
                return None;
            }
        }
        _ => return None,
    };
    let lines: Vec<String> = lines.into_iter().filter(|l| !l.is_empty()).collect();
    (!lines.is_empty()).then_some(lines)
}

fn is_assignment(tok: &str) -> Option<(String, String)> {
    let (name, value) = tok.split_once('=')?;
    let mut chars = name.chars();
    let first = chars.next()?;
    if !(first.is_ascii_alphabetic() || first == '_')
        || !chars.all(|c| c.is_ascii_alphanumeric() || c == '_')
    {
        return None;
    }
    Some((name.to_string(), value.to_string()))
}

fn program_name(tok: &str) -> &str {
    let tok = tok.strip_prefix('\\').unwrap_or(tok);
    tok.rsplit('/').next().unwrap_or(tok)
}

/// Quote a token so the joined text re-parses to the same words.
fn quote_token(s: &str) -> String {
    if !s.is_empty()
        && s.chars()
            .all(|c| c.is_ascii_alphanumeric() || "-_./=:,+@%~^*{}[]".contains(c))
    {
        s.to_string()
    } else {
        format!("'{}'", s.replace('\'', "'\\''"))
    }
}

fn quote_join(tokens: &[String]) -> String {
    tokens
        .iter()
        .map(|t| quote_token(t))
        .collect::<Vec<_>>()
        .join(" ")
}

/// Whether `user` is root (`root`, `#0`, `0`).
fn is_root_user(user: &str) -> bool {
    matches!(user, "root" | "#0" | "0")
}

/// The `-c CMD` / `--command CMD` / `--command=CMD` value among `args`.
fn dash_c_value(args: &[String]) -> Option<(usize, String)> {
    let mut i = 0;
    while i < args.len() {
        let a = args[i].as_str();
        if a == "-c" || a == "--command" {
            return args.get(i + 1).map(|v| (i, v.clone()));
        }
        if let Some(v) = a.strip_prefix("--command=") {
            return Some((i, v.to_string()));
        }
        // A clustered `-c` (`script -qc CMD`, `su -lc CMD`).
        if a.len() > 2
            && a.starts_with('-')
            && !a.starts_with("--")
            && a.ends_with('c')
            && a[1..].chars().all(|c| c.is_ascii_alphabetic())
        {
            return args.get(i + 1).map(|v| (i, v.clone()));
        }
        i += 1;
    }
    None
}

/// Outcome of looking at a wrapper word.
enum Wrap {
    /// Skip to this token index and keep unwrapping.
    Skip(usize),
    /// The wrapper ran its payload (already parsed): nothing else to do.
    Done,
}

/// Unwrap one wrapper word at `tokens[i]` (`sudo`, `su -c`, `env -S`, …).
/// Returns `None` when `tokens[i]` is not a wrapper.
#[allow(clippy::too_many_lines, clippy::many_single_char_names)]
fn unwrap_one(
    tokens: &[String],
    i: usize,
    seg: &mut SegmentTargets,
    segment_env: &mut Vec<(String, Option<String>)>,
    ctx: &mut Recurse<'_>,
) -> Option<Wrap> {
    let n = tokens.len();
    let tok = &tokens[i];
    let prog = program_name(tok);
    let mut j = i + 1;
    let skip_flags = |mut j: usize, value_flags: &[&str]| {
        while let Some(t) = tokens.get(j) {
            if t == "--" {
                return j + 1;
            }
            if !t.starts_with('-') || t == "-" {
                break;
            }
            j += if value_flags.contains(&t.as_str()) {
                2
            } else {
                1
            };
        }
        j
    };
    match prog {
        "sudo" | "doas" => {
            let mut as_root = true;
            while let Some(opt) = tokens.get(j) {
                if !opt.starts_with('-') {
                    break;
                }
                if opt == "--" {
                    j += 1;
                    break;
                }
                // `sudo -D DIR` / `--chdir=DIR`: the command runs in DIR.
                if opt == "-D" || opt == "--chdir" {
                    seg.chdir = tokens.get(j + 1).cloned();
                } else if let Some(d) = opt
                    .strip_prefix("--chdir=")
                    .or_else(|| opt.strip_prefix("-D").filter(|d| !d.is_empty()))
                {
                    seg.chdir = Some(d.to_string());
                }
                // `-iu USER`, `-uUSER`, `--user=USER`: a cluster, as sudo
                // reads it.
                let (words_used, run_as) =
                    crate::parser::privilege_option(opt, tokens.get(j + 1).map(String::as_str));
                if let Some(name) = run_as {
                    as_root = is_root_user(&name);
                }
                j += words_used;
            }
            if as_root {
                seg.sudo_root = true;
                seg.root_tool = Some(prog.to_string());
            }
            Some(Wrap::Skip(j))
        }
        "env" => {
            while let Some(opt) = tokens.get(j) {
                // `env -S 'cmd args'` splits the string into the command.
                let split = if opt == "-S" || opt == "--split-string" {
                    tokens.get(j + 1).map(|v| (v.clone(), j + 2))
                } else {
                    opt.strip_prefix("--split-string=")
                        .or_else(|| opt.strip_prefix("-S").filter(|v| !v.is_empty()))
                        .map(|v| (v.to_string(), j + 1))
                };
                if let Some((text, next)) = split {
                    let mut payload = text;
                    if next < n {
                        payload.push(' ');
                        payload.push_str(&quote_join(&tokens[next..]));
                    }
                    ctx.recurse(&payload, seg, segment_env);
                    return Some(Wrap::Done);
                }
                if matches!(opt.as_str(), "-u" | "--unset") {
                    if let Some(v) = tokens.get(j + 1) {
                        segment_env.push((v.clone(), None));
                    }
                    j += 2;
                } else if matches!(opt.as_str(), "-C" | "--chdir") {
                    seg.chdir = tokens.get(j + 1).cloned();
                    j += 2;
                } else if let Some(d) = opt
                    .strip_prefix("--chdir=")
                    .or_else(|| opt.strip_prefix("-C").filter(|d| !d.is_empty()))
                {
                    seg.chdir = Some(d.to_string());
                    j += 1;
                } else if opt.starts_with('-') {
                    j += 1;
                } else if let Some((k, v)) = is_assignment(opt) {
                    segment_env.push((k, Some(v)));
                    j += 1;
                } else {
                    break;
                }
            }
            Some(Wrap::Skip(j))
        }
        // `su [-] [-l] [user] -c CMD`: runs CMD as `user` (root by default).
        "su" => {
            let mut user: Option<&str> = None;
            let mut k = j;
            while let Some(t) = tokens.get(k) {
                match t.as_str() {
                    "-c"
                    | "--command"
                    | "-s"
                    | "--shell"
                    | "-g"
                    | "--group"
                    | "-G"
                    | "--supp-group"
                    | "-w"
                    | "--whitelist-environment" => k += 2,
                    // A clustered `-c` (`su -lc CMD`) takes the next word.
                    s if s.len() > 2
                        && s.starts_with('-')
                        && !s.starts_with("--")
                        && s.ends_with('c') =>
                    {
                        k += 2;
                    }
                    s if s.starts_with('-') => k += 1,
                    s => {
                        if user.is_none() {
                            user = Some(s);
                        }
                        k += 1;
                    }
                }
            }
            if user.is_none_or(is_root_user) {
                seg.sudo_root = true;
                seg.root_tool = Some(prog.to_string());
            }
            if let Some((_, payload)) = dash_c_value(&tokens[j..]) {
                ctx.recurse(&payload, seg, segment_env);
            }
            Some(Wrap::Done)
        }
        // `runuser [-l] user -c CMD` / `runuser -u user -- CMD`.
        "runuser" => {
            let rest = &tokens[j..];
            let user = flag_value(rest, &["-u", "--user"]).or_else(|| {
                let mut k = 0;
                while let Some(t) = rest.get(k) {
                    if matches!(t.as_str(), "-c" | "--command" | "-g" | "-G" | "-s") {
                        k += 2;
                    } else if t.starts_with('-') {
                        k += 1;
                    } else {
                        return Some(t.clone());
                    }
                }
                None
            });
            if user.as_deref().is_none_or(is_root_user) {
                seg.sudo_root = true;
                seg.root_tool = Some(prog.to_string());
            }
            if let Some((_, payload)) = dash_c_value(rest) {
                ctx.recurse(&payload, seg, segment_env);
                return Some(Wrap::Done);
            }
            Some(Wrap::Skip(skip_flags(
                j,
                &["-u", "--user", "-g", "--group", "-G", "--supp-group"],
            )))
        }
        "pkexec" => {
            let mut as_root = true;
            while let Some(t) = tokens.get(j) {
                if t == "--user" {
                    as_root = tokens.get(j + 1).is_some_and(|u| is_root_user(u));
                    j += 2;
                } else if t.starts_with('-') {
                    j += 1;
                } else {
                    break;
                }
            }
            if as_root {
                seg.sudo_root = true;
                seg.root_tool = Some(prog.to_string());
            }
            Some(Wrap::Skip(j))
        }
        // `flock [opts] FILE -c CMD` / `flock [opts] FILE CMD…`.
        "flock" => {
            if let Some((_, payload)) = dash_c_value(&tokens[j..]) {
                ctx.recurse(&payload, seg, segment_env);
                return Some(Wrap::Done);
            }
            let j = skip_flags(j, &["-w", "--timeout", "-E", "--conflict-exit-code"]);
            Some(Wrap::Skip(j + 1))
        }
        // `script [opts] -c CMD [file]`; without `-c` it starts a shell.
        "script" => {
            if let Some((_, payload)) = dash_c_value(&tokens[j..]) {
                ctx.recurse(&payload, seg, segment_env);
            }
            Some(Wrap::Done)
        }
        "chroot" => {
            let j = skip_flags(j, &["--userspec", "--groups"]);
            Some(Wrap::Skip(j + 1))
        }
        "nice" | "ionice" | "timeout" | "chrt" | "taskset" => {
            let value_flags: &[&str] = match prog {
                "nice" => &["-n", "--adjustment"],
                "ionice" => &["-c", "--class", "-n", "--classdata", "-t"],
                "timeout" => &["-s", "--signal", "-k", "--kill-after"],
                "chrt" => &["-T", "-P", "-D"],
                _ => &["-c", "--cpu-list"],
            };
            let had_list = prog == "taskset"
                && tokens[j..]
                    .iter()
                    .take_while(|t| t.starts_with('-'))
                    .any(|t| t == "-c" || t == "--cpu-list");
            let mut j = skip_flags(j, value_flags);
            // `timeout DURATION`, `chrt PRIORITY`, `taskset MASK` operands.
            let operand = match prog {
                "timeout" | "chrt" => true,
                "taskset" => !had_list,
                _ => false,
            };
            if operand && j < n {
                j += 1;
            }
            Some(Wrap::Skip(j))
        }
        "unshare" | "nsenter" => {
            // Entering another process' namespaces needs root (`nsenter -t 1
            // -m …` acts on the host's mount namespace).
            if prog == "nsenter" {
                seg.sudo_root = true;
                seg.root_tool = Some(prog.to_string());
            }
            let value_flags: &[&str] = if prog == "nsenter" {
                &["-t", "--target", "-S", "--setuid", "-G", "--setgid"]
            } else {
                &["--map-user", "--map-group", "--setgroups", "--propagation"]
            };
            Some(Wrap::Skip(skip_flags(j, value_flags)))
        }
        "strace" | "ltrace" => Some(Wrap::Skip(skip_flags(
            j,
            &[
                "-e", "-o", "-p", "-s", "-u", "-E", "-a", "-b", "-I", "-O", "-S", "-P", "-X",
            ],
        ))),
        "xargs" => {
            // GNU `-i[R]`, `-l[N]`, `-e[S]` take an optional value glued to
            // the flag only: a bare `-i` is followed by the command.
            // `-I R` / `-iR` / `--replace=R`: R in the command is a value
            // read from input (spelled `{}`, unknown here).
            let mut replace: Option<String> = None;
            while let Some(t) = tokens.get(j) {
                if t == "--" {
                    j += 1;
                    break;
                }
                if !t.starts_with('-') || t == "-" {
                    break;
                }
                if t == "-I" || t == "-J" {
                    replace = tokens.get(j + 1).cloned();
                    j += 2;
                    continue;
                }
                if t == "-i" || t == "--replace" {
                    replace = Some("{}".to_string());
                } else if let Some(r) = t
                    .strip_prefix("--replace=")
                    .or_else(|| t.strip_prefix("-I").filter(|r| !r.is_empty()))
                    .or_else(|| t.strip_prefix("-i").filter(|r| !r.is_empty()))
                {
                    replace = Some(r.to_string());
                } else if matches!(
                    t.as_str(),
                    "-n" | "-P"
                        | "-L"
                        | "-s"
                        | "-d"
                        | "-E"
                        | "-a"
                        | "--max-args"
                        | "--max-procs"
                        | "--max-lines"
                        | "--delimiter"
                        | "--arg-file"
                ) {
                    j += 1;
                }
                j += 1;
            }
            // `echo feature/login | xargs -I{} git push … {}`: the input is
            // known, so is the value.
            let piped = ctx.state.pipe_values.take();
            if let (Some(r), Some(values)) = (replace.as_ref().filter(|r| !r.is_empty()), piped) {
                if j < n {
                    for v in values.iter().take(16) {
                        let rewritten: Vec<String> = tokens[j..]
                            .iter()
                            .map(|t| t.replace(r.as_str(), v))
                            .collect();
                        ctx.recurse(&quote_join(&rewritten), seg, segment_env);
                    }
                    return Some(Wrap::Done);
                }
            }
            match replace.filter(|r| !r.is_empty() && r != "{}") {
                Some(r) if j < n => {
                    let rewritten: Vec<String> = tokens[j..]
                        .iter()
                        .map(|t| t.replace(r.as_str(), "{}"))
                        .collect();
                    ctx.recurse(&quote_join(&rewritten), seg, segment_env);
                    Some(Wrap::Done)
                }
                _ => Some(Wrap::Skip(j)),
            }
        }
        // `parallel CMD ::: A B`: CMD once per argument (`{}` is the
        // argument, else it is appended), like a loop over a literal list.
        "parallel" if tokens[j..].iter().any(|t| t == ":::") => {
            let k = skip_flags(
                j,
                &[
                    "-j",
                    "--jobs",
                    "-N",
                    "-S",
                    "--sshlogin",
                    "--delay",
                    "--timeout",
                ],
            );
            let sep = tokens[k..].iter().position(|t| t == ":::").map(|p| p + k)?;
            let cmd = &tokens[k..sep];
            if cmd.is_empty() {
                return Some(Wrap::Done);
            }
            for arg in tokens[sep + 1..]
                .iter()
                .take_while(|t| *t != ":::" && *t != "::::")
                .take(16)
            {
                let mut c: Vec<String> = cmd.to_vec();
                if c.iter().any(|t| t.contains("{}")) {
                    for t in &mut c {
                        *t = t.replace("{}", arg);
                    }
                } else {
                    c.push(arg.clone());
                }
                ctx.recurse(&quote_join(&c), seg, segment_env);
            }
            Some(Wrap::Done)
        }
        "watch" => Some(Wrap::Skip(skip_flags(
            j,
            &["-n", "--interval", "-d", "-q", "--equexit"],
        ))),
        "command" | "exec" | "nohup" | "builtin" | "time" | "noglob" | "nocorrect" | "-"
        | "setsid" | "stdbuf" | "busybox" | "coproc" => Some(Wrap::Skip(skip_flags(j, &[]))),
        // Compound-command keywords: the rest is an ordinary command.
        "if" | "then" | "else" | "elif" | "do" | "while" | "until" | "!" | "{" | "}" => {
            Some(Wrap::Skip(j))
        }
        _ => None,
    }
}

/// Recursion context for wrapper payloads.
struct Recurse<'a> {
    out: &'a mut CommandTargets,
    state: &'a mut LineState,
    inh: &'a Inherit,
    depth: usize,
}

impl Recurse<'_> {
    /// Parse `payload` as commands that inherit the wrapper's root / place /
    /// inline environment.
    fn recurse(
        &mut self,
        payload: &str,
        seg: &SegmentTargets,
        segment_env: &[(String, Option<String>)],
    ) {
        let mut inh = self.inh.clone();
        inh.sudo_root = seg.sudo_root;
        inh.root_tool.clone_from(&seg.root_tool);
        inh.env.extend(segment_env.iter().cloned());
        // `B=main bash -c 'git push -f origin $B'`: the payload's `$B` is
        // the value the command sets for it, whatever `B` was before.
        let saved: Vec<(String, Option<Vec<String>>)> = segment_env
            .iter()
            .map(|(k, v)| {
                let old = match v {
                    Some(v) => self.state.vars.insert(k.clone(), vec![v.clone()]),
                    None => self.state.vars.remove(k),
                };
                (k.clone(), old)
            })
            .collect();
        parse_into(payload, self.out, self.state, &inh, self.depth + 1);
        for (k, old) in saved.into_iter().rev() {
            match old {
                Some(v) => self.state.vars.insert(k, v),
                None => self.state.vars.remove(&k),
            };
        }
    }
}

#[allow(clippy::too_many_lines)]
fn parse_segment(
    tokens: &[String],
    out: &mut CommandTargets,
    state: &mut LineState,
    inh: &Inherit,
    depth: usize,
) {
    let mut seg = SegmentTargets {
        text: quote_join(tokens),
        place: inh.place.clone(),
        sudo_root: inh.sudo_root,
        root_tool: inh.root_tool.clone(),
        ..SegmentTargets::default()
    };
    let mut segment_env: Vec<(String, Option<String>)> = Vec::new();

    // Strip env assignments and command wrappers.
    let mut i = 0;
    while let Some(tok) = tokens.get(i) {
        if let Some((k, v)) = is_assignment(tok) {
            segment_env.push((k, Some(v)));
            i += 1;
            continue;
        }
        let mut rec = Recurse {
            out,
            state,
            inh,
            depth,
        };
        match unwrap_one(tokens, i, &mut seg, &mut segment_env, &mut rec) {
            Some(Wrap::Skip(j)) => i = j.max(i + 1),
            Some(Wrap::Done) => return,
            None => break,
        }
    }

    let Some(prog_tok) = tokens.get(i) else {
        // `C=prod-eu` alone: a shell variable for later commands.
        for (k, v) in segment_env {
            if let Some(v) = v {
                state.vars.insert(k, vec![v]);
            }
        }
        return;
    };
    let prog = program_name(prog_tok);
    let args = &tokens[i + 1..];
    // `for c in prod-eu dev; do …`: `$c` takes each value.
    if prog == "for" {
        if let [var, kw, values @ ..] = args {
            if kw == "in" && !values.is_empty() {
                state.vars.insert(var.clone(), values.to_vec());
            }
        }
        return;
    }
    if matches!(prog, "cd" | "pushd") {
        if let Some(d) = args
            .iter()
            .find(|a| !a.starts_with('-') && !a.starts_with('+'))
        {
            state.cwd = match state.cwd.take() {
                Some(c) if !d.starts_with('/') && !d.starts_with('~') => {
                    // Bounded: past the limit the directory is unknown.
                    (c.len() + d.len() < MAX_TARGET_DIR_LEN)
                        .then(|| crate::parser::normalize_path(&format!("{c}/{d}")))
                }
                _ => Some(crate::parser::normalize_path(d)),
            };
        }
    }

    // `export KUBECONFIG=…;`, `declare -x NODE_ENV=production`, `local
    // b=…` (a function body), `unset X`: the change applies to every
    // *later* command of the line.
    match prog {
        "export" | "declare" | "typeset" | "readonly" | "local" => {
            for t in args {
                if let Some((k, v)) = is_assignment(t) {
                    state.env.push((k, Some(v)));
                }
            }
            return;
        }
        "unset" => {
            for t in args.iter().filter(|t| !t.starts_with('-')) {
                state.env.push((t.clone(), None));
            }
            return;
        }
        _ => {}
    }

    seg.env.clone_from(&state.env);
    seg.env.extend(inh.env.iter().cloned());
    seg.env.extend(segment_env.iter().cloned());
    seg.kubeconfig = seg.line_var("KUBECONFIG").flatten();
    seg.k8s_namespace.clone_from(&state.k8s_namespace);
    seg.tf_workspace.clone_from(&state.tf_workspace);
    if !state.tf_switch_certain {
        seg.tf_fallbacks.clone_from(&state.tf_fallbacks);
    }
    seg.gcp_project.clone_from(&state.gcp_project);
    seg.azure_subscription.clone_from(&state.azure_subscription);
    seg.git_branch_switch.clone_from(&state.git_branch);
    if seg.git_branch_switch.is_some() {
        seg.git_fallbacks.clone_from(&state.git_fallbacks);
        seg.git_fallbacks_always = !state.git_switch_certain;
        seg.git_switch_creates = state.git_switch_creates;
    }
    if seg.place == Place::Pod {
        seg.k8s_context.clone_from(&inh.k8s_context);
        seg.k8s_context_unknown = inh.k8s_unknown;
        seg.kubeconfig.clone_from(&inh.kubeconfig);
        seg.k8s_namespace.clone_from(&inh.k8s_namespace);
        seg.k8s_fallbacks.clone_from(&inh.k8s_fallbacks);
        seg.k8s_fallbacks_always = inh.k8s_fallbacks_always;
    }

    match prog {
        // Fleet tools: `ansible PATTERN -m shell -a CMD [-b]`,
        // `ansible-playbook -i INV site.yml [-b]`, `pdsh -w HOSTS CMD`,
        // `pssh -h FILE CMD`, `clush -w HOSTS CMD`: CMD runs on every host of
        // the pattern (`-b` / `--become`: as root).
        "ansible" | "ansible-playbook" | "pdsh" | "pssh" | "parallel-ssh" | "clush" => {
            let value = |flags: &[&str]| -> Option<String> {
                args.iter().enumerate().find_map(|(k, a)| {
                    if flags.contains(&a.as_str()) {
                        return args.get(k + 1).cloned();
                    }
                    flags
                        .iter()
                        .find_map(|f| a.strip_prefix(&format!("{f}=")).map(str::to_string))
                })
            };
            let (hosts, payload) = match prog {
                "ansible" => {
                    let module = value(&["-m", "--module-name"]);
                    let shell_module = module.as_deref().is_none_or(|m| {
                        matches!(
                            m.rsplit('.').next().unwrap_or(m),
                            "shell" | "command" | "raw"
                        )
                    });
                    (
                        args.iter().find(|a| !a.starts_with('-')).cloned(),
                        value(&["-a", "--args"]).filter(|_| shell_module),
                    )
                }
                "ansible-playbook" => (value(&["-i", "--inventory", "-l", "--limit"]), None),
                _ => {
                    const VAL: &[&str] = &[
                        "-h", "-H", "-l", "-p", "-t", "-o", "-e", "-x", "-X", "-O", "-w", "-R",
                        "-f", "-u", "-g", "-L",
                    ];
                    let mut k = 0;
                    while k < args.len() && args[k].starts_with('-') {
                        k += if VAL.contains(&args[k].as_str()) {
                            2
                        } else {
                            1
                        };
                    }
                    (
                        value(&["-w", "-H", "-h", "-g"]),
                        (k < args.len()).then(|| args[k..].join(" ")),
                    )
                }
            };
            let become_root = prog.starts_with("ansible")
                && args.iter().any(|a| matches!(a.as_str(), "-b" | "--become"))
                && value(&["--become-user"]).is_none_or(|u| is_root_user(&u));
            let host = hosts.unwrap_or_else(|| "*".to_string());
            seg.place = Place::Host(host.clone());
            seg.env.clear();
            if become_root {
                seg.sudo_root = true;
                seg.root_tool = Some(format!("{prog} --become"));
            }
            out.segments.push(seg);
            if let Some(text) = payload {
                let inh = Inherit {
                    place: Place::Host(host),
                    sudo_root: become_root,
                    root_tool: become_root.then(|| format!("{prog} --become")),
                    ..Inherit::default()
                };
                parse_into(&text, out, &mut LineState::default(), &inh, depth + 1);
            }
            return;
        }
        // `ssh [opts] host CMD…`: the payload runs on `host`, in a fresh
        // shell there (switches inside it do not leak back here).
        "ssh" => {
            let Some((host, at)) = ssh_host(args) else {
                return;
            };
            seg.place = Place::Host(host.clone());
            seg.env.clear();
            seg.git_branch_switch = None;
            seg.k8s_namespace = None;
            seg.tf_workspace = None;
            seg.gcp_project = None;
            seg.azure_subscription = None;
            seg.kubeconfig = None;
            seg.sudo_root = false;
            seg.root_tool = None;
            out.segments.push(seg);
            let mut payload = &args[at + 1..];
            if payload.first().is_some_and(|a| a == "--") {
                payload = &payload[1..];
            }
            if !payload.is_empty() {
                let text = payload.join(" ");
                let inh = Inherit {
                    place: Place::Host(host),
                    ..Inherit::default()
                };
                parse_into(&text, out, &mut LineState::default(), &inh, depth + 1);
            }
            return;
        }
        // `heroku run CMD`, `heroku pg:psql -c SQL`, `fly ssh console -C
        // CMD`, `render ssh SERVICE -- CMD`: CMD runs on the platform's app
        // (`remote=heroku:APP`; a production app name escalates).
        "heroku" | "fly" | "flyctl" | "render" => {
            let mut words: Vec<&str> = vec![prog];
            words.extend(args.iter().map(String::as_str));
            if let Some(r) = crate::parser::paas_remote_command(&words) {
                seg.place = Place::Host(r.target.clone());
                seg.env.clear();
                seg.git_branch_switch = None;
                seg.sudo_root = false;
                seg.root_tool = None;
                out.segments.push(seg);
                let inh = Inherit {
                    place: Place::Host(r.target),
                    ..Inherit::default()
                };
                parse_into(&r.command, out, &mut LineState::default(), &inh, depth + 1);
                return;
            }
        }
        "docker" | "podman" if args.first().is_some_and(|a| a == "exec") => {
            const VAL: &[&str] = &[
                "-e",
                "--env",
                "-u",
                "--user",
                "-w",
                "--workdir",
                "--env-file",
                "--detach-keys",
            ];
            let mut k = 1;
            while k < args.len() && args[k].starts_with('-') {
                k += if VAL.contains(&args[k].as_str()) {
                    2
                } else {
                    1
                };
            }
            seg.place = Place::Container;
            seg.env.clear();
            seg.git_branch_switch = None;
            out.segments.push(seg);
            if k + 1 < args.len() {
                let text = quote_join(&args[k + 1..]);
                let inh = Inherit {
                    place: Place::Container,
                    ..Inherit::default()
                };
                parse_into(&text, out, &mut LineState::default(), &inh, depth + 1);
            }
            return;
        }
        _ => {}
    }

    // `argocd … --kube-context X` (core mode) acts on the cluster of that
    // context; without it, on the Argo CD server's clusters (`--server`).
    if prog == "argocd"
        && args
            .iter()
            .any(|a| a == "--kube-context" || a.starts_with("--kube-context="))
    {
        seg.mentions_k8s = true;
        parse_k8s_args(args, &mut seg, state);
    }
    if K8S_PROGRAMS.contains(&prog) {
        seg.mentions_k8s = true;
        // `kubectl exec pod -- cmd`: only the part before `--` is kubectl's.
        let end = args.iter().position(|a| a == "--").unwrap_or(args.len());
        // helm reads its context from `HELM_KUBECONTEXT` (inline or exported
        // earlier on the line) unless `--kube-context` is given.
        let helm_ctx = (prog == "helm"
            && !args[..end]
                .iter()
                .any(|a| a == "--kube-context" || a.starts_with("--kube-context=")))
        .then(|| seg.line_var("HELM_KUBECONTEXT").flatten())
        .flatten();
        if let Some(c) = helm_ctx {
            let mut with_ctx = vec!["--kube-context".to_string(), c];
            with_ctx.extend(args[..end].iter().cloned());
            parse_k8s_args(&with_ctx, &mut seg, state);
        } else {
            parse_k8s_args(&args[..end], &mut seg, state);
        }
        let is_exec = args[..end]
            .iter()
            .filter(|a| !a.starts_with('-'))
            .any(|a| matches!(a.as_str(), "exec" | "debug" | "run" | "attach"));
        if is_exec && end + 1 < args.len() {
            let pod = Inherit {
                place: Place::Pod,
                sudo_root: false,
                root_tool: None,
                env: Vec::new(),
                k8s_context: seg.k8s_context.clone(),
                k8s_unknown: seg.k8s_context_unknown,
                kubeconfig: seg.kubeconfig.clone(),
                k8s_namespace: seg.k8s_namespace.clone(),
                k8s_fallbacks: seg.k8s_fallbacks.clone(),
                k8s_fallbacks_always: seg.k8s_fallbacks_always,
            };
            let text = quote_join(&args[end + 1..]);
            out.segments.push(seg);
            parse_into(&text, out, &mut LineState::default(), &pod, depth + 1);
            return;
        }
    } else if matches!(prog, "kubectx" | "kubens" | "kubie") {
        seg.switch_only = true;
        let pos: Vec<&String> = args.iter().filter(|a| !a.starts_with('-')).collect();
        // `kubie exec CTX NS CMD…`: CMD runs in CTX.
        if prog == "kubie" && pos.first().is_some_and(|v| *v == "exec") && pos.len() >= 4 {
            let ctx_name = pos[1].clone();
            let ns = pos[2].clone();
            let at = args
                .iter()
                .enumerate()
                .filter(|(_, a)| !a.starts_with('-'))
                .nth(3)
                .map_or(args.len(), |(k, _)| k);
            out.segments.push(seg);
            let mut st = LineState {
                k8s_context: Some(ctx_name),
                k8s_namespace: Some(ns),
                k8s_switch_certain: true,
                ..LineState::default()
            };
            parse_into(&quote_join(&args[at..]), out, &mut st, inh, depth + 1);
            return;
        }
        let (what, value) = match (prog, pos.as_slice()) {
            ("kubie", [verb, v, ..]) if *verb == "ctx" => ("ctx", Some(*v)),
            ("kubie", [verb, v, ..]) if *verb == "ns" => ("ns", Some(*v)),
            // `kubectx new=old` renames a context; it does not switch.
            ("kubectx", [v, ..]) if v.contains('=') => ("", None),
            ("kubectx", [v, ..]) => ("ctx", Some(*v)),
            ("kubens", [v, ..]) => ("ns", Some(*v)),
            _ => ("", None),
        };
        if args.iter().any(|a| a == "-") && value.is_none() {
            // `kubectx -` / `kubens -`: back to the previous one (unknown).
            if prog == "kubectx" {
                state.k8s_context = None;
                state.k8s_unknown = true;
            } else {
                state.k8s_namespace = None;
            }
        }
        match (what, value) {
            ("ctx", Some(v)) => {
                state.k8s_context = Some(v.clone());
                state.k8s_unknown = false;
                // `kubie ctx X -n ns`
                if let Some(ns) = flag_value(args, &["-n", "--namespace"]) {
                    state.k8s_namespace = Some(ns);
                }
            }
            ("ns", Some(v)) => state.k8s_namespace = Some(v.clone()),
            _ => {}
        }
    } else if tokens[i..]
        .iter()
        .any(|t| K8S_PROGRAMS.contains(&program_name(t)))
    {
        // e.g. `parallel kubectl delete`, `nice kubectl ...`
        seg.mentions_k8s = true;
        let mut scratch = LineState::default();
        parse_k8s_args(args, &mut seg, &mut scratch);
        if seg.k8s_context.is_none() && !seg.k8s_context_unknown {
            seg.k8s_context.clone_from(&state.k8s_context);
            seg.k8s_context_unknown = state.k8s_unknown;
            seg.k8s_fallbacks.clone_from(&state.k8s_fallbacks);
            seg.k8s_fallbacks_always = !state.k8s_switch_certain;
        }
    }

    seg.cluster = cluster_target(prog, args);
    // `env -C DIR cmd`: cmd runs in DIR (relative to the line's directory).
    let run_dir = seg.chdir.as_deref().map(|d| match state.cwd.as_ref() {
        Some(c) if !d.starts_with('/') && !d.starts_with('~') => {
            crate::parser::normalize_path(&format!("{c}/{d}"))
        }
        _ => crate::parser::normalize_path(d),
    });
    let line_dir = run_dir.or_else(|| state.cwd.clone());
    match prog {
        "git" => {
            parse_git(args, &mut seg, state);
            let dash_c = args
                .iter()
                .take_while(|a| a.starts_with('-'))
                .position(|a| a == "-C")
                .and_then(|p| args.get(p + 1));
            seg.git_dir = match (dash_c, line_dir.as_ref()) {
                (Some(d), Some(c)) if !d.starts_with('/') && !d.starts_with('~') => {
                    Some(crate::parser::normalize_path(&format!("{c}/{d}")))
                }
                (Some(d), _) => Some(d.clone()),
                (None, c) => c.cloned(),
            };
        }
        "aws" => {
            if let Some(v) = flag_value(args, &["--profile"]) {
                seg.aws_profile = Some(v);
            }
        }
        "gcloud" => {
            let pos: Vec<&String> = args.iter().filter(|a| !a.starts_with('-')).collect();
            if let Some(v) = flag_value(args, &["--project"]) {
                seg.gcp_project = Some(v);
            } else if let Some(w) = pos.windows(4).find(|w| {
                w[0] == "config" && w[1] == "set" && (w[2] == "project" || w[2] == "core/project")
            }) {
                state.gcp_project = Some(w[3].clone());
                seg.switch_only = true;
            } else if let Some(w) = pos.windows(3).find(|w| w[0] == "projects") {
                // `gcloud projects delete|undelete|describe ID`
                if !matches!(w[1].as_str(), "list" | "create") {
                    seg.gcp_project = Some(w[2].clone());
                }
            }
        }
        "az" => {
            let pos: Vec<&String> = args.iter().filter(|a| !a.starts_with('-')).collect();
            if pos.len() >= 2 && pos[0] == "account" && pos[1] == "set" {
                if let Some(v) = flag_value(args, &["--subscription", "-s", "--name", "-n"]) {
                    state.azure_subscription = Some(v);
                    seg.switch_only = true;
                }
            } else if let Some(v) = flag_value(args, &["--subscription"]) {
                seg.azure_subscription = Some(v);
            }
        }
        "terraform" | "tofu" | "terragrunt" => {
            seg.terraform = true;
            seg.tf_dir.clone_from(&line_dir);
            // `-chdir=DIR`; terragrunt `--terragrunt-working-dir DIR` /
            // `--working-dir DIR`.
            let tg_dir = args
                .iter()
                .position(|a| matches!(a.as_str(), "--terragrunt-working-dir" | "--working-dir"))
                .and_then(|k| args.get(k + 1))
                .map(String::as_str);
            if let Some(d) = args
                .iter()
                .find_map(|a| {
                    a.strip_prefix("-chdir=")
                        .or_else(|| a.strip_prefix("--chdir="))
                        .or_else(|| a.strip_prefix("--terragrunt-working-dir="))
                        .or_else(|| a.strip_prefix("--working-dir="))
                })
                .or(tg_dir)
            {
                // `-chdir=$ENV`: the values the line gives it, else unknown.
                if d.contains(['$', '`']) {
                    let values = expand_line_value(d, state);
                    seg.tf_dir_unknown = values.is_empty();
                    seg.tf_dir_hints.extend(values);
                }
                seg.tf_dir = Some(match line_dir {
                    Some(ref c) if !d.starts_with('/') && !d.starts_with('~') => {
                        crate::parser::normalize_path(&format!("{c}/{d}"))
                    }
                    _ => crate::parser::normalize_path(d),
                });
                seg.tf_dir_hints.extend(seg.tf_dir.clone());
            }
            let pos: Vec<&String> = args.iter().filter(|a| !a.starts_with('-')).collect();
            if let [ws, verb, name, ..] = pos.as_slice() {
                if *ws == "workspace" && matches!(verb.as_str(), "select" | "new") {
                    state.tf_workspace = Some((*name).clone());
                    seg.switch_only = true;
                }
            }
            seg.tf_dir_hints.extend(line_dir.clone());
            let mut k = 0;
            while let Some(a) = args.get(k) {
                if let Some(v) = a
                    .strip_prefix("-chdir=")
                    .or_else(|| a.strip_prefix("--chdir="))
                    .or_else(|| a.strip_prefix("-var-file="))
                    .or_else(|| a.strip_prefix("--var-file="))
                {
                    seg.tf_dir_hints.push(crate::parser::normalize_path(v));
                } else if matches!(a.as_str(), "-var-file" | "--var-file") {
                    seg.tf_dir_hints.extend(args.get(k + 1).cloned());
                    k += 1;
                }
                k += 1;
            }
        }
        "sh" | "bash" | "zsh" | "dash" | "ksh" | "mksh" | "yash" | "fish" | "ash" | "nu"
        | "nushell" | "elvish" | "xonsh" | "osh" | "ysh" | "pwsh" | "powershell" => {
            if let Some(pos) = args.iter().position(|a| {
                a.len() > 1
                    && a.starts_with('-')
                    && !a.starts_with("--")
                    && a[1..].chars().all(|c| c.is_ascii_alphabetic())
                    && (a.contains('c') || a.eq_ignore_ascii_case("-command"))
            }) {
                if let Some(script) = args.get(pos + 1) {
                    Recurse {
                        out,
                        state,
                        inh,
                        depth,
                    }
                    .recurse(script, &seg, &segment_env);
                    return;
                }
            }
        }
        "eval" => {
            let mut inh = inh.clone();
            inh.sudo_root = seg.sudo_root;
            inh.root_tool.clone_from(&seg.root_tool);
            inh.env.extend(segment_env);
            parse_into(&args.join(" "), out, state, &inh, depth + 1);
            return;
        }
        _ => {}
    }
    out.segments.push(seg);
}

/// The cluster a cluster-lifecycle command deletes / upgrades by name:
/// `eksctl delete|upgrade cluster [--name] X`, `aws eks delete-cluster
/// --name X`, `gcloud container clusters delete|upgrade X`, `az aks
/// delete|stop -n X`, `doctl kubernetes cluster delete X`.
fn cluster_target(prog: &str, args: &[String]) -> Option<String> {
    let pos: Vec<&String> = args.iter().filter(|a| !a.starts_with('-')).collect();
    let named = || flag_value(args, &["--name", "-n", "--cluster"]);
    match (prog, pos.as_slice()) {
        ("eksctl", [verb, kind, rest @ ..])
            if matches!(verb.as_str(), "delete" | "upgrade")
                && matches!(kind.as_str(), "cluster" | "clusters") =>
        {
            named().or_else(|| rest.first().map(|s| (*s).clone()))
        }
        ("aws", [svc, verb, ..])
            if svc.as_str() == "eks"
                && matches!(verb.as_str(), "delete-cluster" | "update-cluster-version") =>
        {
            flag_value(args, &["--name"])
        }
        ("gcloud", [.., c, cl, verb, name] | [.., c, cl, verb, name, _])
            if c.as_str() == "container"
                && cl.as_str() == "clusters"
                && matches!(verb.as_str(), "delete" | "upgrade" | "resize") =>
        {
            Some((*name).clone())
        }
        ("az", [svc, verb, ..])
            if svc.as_str() == "aks" && matches!(verb.as_str(), "delete" | "stop" | "upgrade") =>
        {
            named()
        }
        // The Argo CD server (`--server argocd.prod.example.com`).
        ("argocd", _) => flag_value(args, &["--server"]),
        ("doctl", [k, c, verb, name, ..])
            if matches!(k.as_str(), "kubernetes" | "k8s" | "k")
                && c.as_str() == "cluster"
                && matches!(verb.as_str(), "delete" | "upgrade") =>
        {
            Some((*name).clone())
        }
        _ => None,
    }
}

/// The value of one of `flags` (`--flag v` or `--flag=v`), last one wins.
fn flag_value(args: &[String], flags: &[&str]) -> Option<String> {
    let mut found = None;
    let mut i = 0;
    while i < args.len() {
        let a = args[i].as_str();
        if flags.contains(&a) {
            if let Some(v) = args.get(i + 1) {
                found = Some(v.clone());
                i += 1;
            }
        } else if let Some((f, v)) = a.split_once('=') {
            if flags.contains(&f) {
                found = Some(v.to_string());
            }
        }
        i += 1;
    }
    found
}

/// The host of an `ssh [options] [user@]host [command…]` invocation, and its
/// index in `args`.
fn ssh_host(args: &[String]) -> Option<(String, usize)> {
    const VAL: &[&str] = &[
        "-b", "-c", "-D", "-E", "-e", "-F", "-I", "-i", "-J", "-L", "-l", "-m", "-O", "-o", "-p",
        "-Q", "-R", "-S", "-W", "-w", "-B",
    ];
    let mut i = 0;
    while i < args.len() && args[i].starts_with('-') {
        i += if VAL.contains(&args[i].as_str()) {
            2
        } else {
            1
        };
    }
    let host = args.get(i)?;
    let host = host.rsplit_once('@').map_or(host.as_str(), |(_, h)| h);
    (!host.is_empty()).then(|| (host.to_string(), i))
}

fn parse_k8s_args(args: &[String], seg: &mut SegmentTargets, state: &mut LineState) {
    // `kubectl config use-context X` (alias `use`) switches the context for
    // the commands that follow; `kubectl config set-context --current
    // --namespace=X` the namespace.
    let positional: Vec<&String> = args.iter().filter(|a| !a.starts_with('-')).collect();
    if let [cfg, verb, rest @ ..] = positional.as_slice() {
        if *cfg == "config" && matches!(verb.as_str(), "use-context" | "use") {
            if let Some(v) = rest.first() {
                state.k8s_context = Some((*v).clone());
                state.k8s_unknown = false;
            }
            seg.switch_only = true;
            return;
        }
        if *cfg == "config"
            && verb.as_str() == "set-context"
            && args.iter().any(|a| a == "--current")
        {
            if let Some(ns) = flag_value(args, &["--namespace", "-n"]) {
                state.k8s_namespace = Some(ns);
            }
            seg.switch_only = true;
            return;
        }
    }
    let mut explicit_ctx = None;
    let mut i = 0;
    while i < args.len() {
        let a = args[i].as_str();
        let next = args.get(i + 1).cloned();
        if a == "--context" || a == "--kube-context" || a == "--kubecontext" {
            if let Some(v) = next {
                explicit_ctx = Some(v);
                i += 1;
            }
        } else if let Some(v) = a
            .strip_prefix("--context=")
            .or_else(|| a.strip_prefix("--kube-context="))
            .or_else(|| a.strip_prefix("--kubecontext="))
        {
            explicit_ctx = Some(v.to_string());
        } else if a == "--kubeconfig" {
            if let Some(v) = next {
                seg.kubeconfig = Some(v);
                i += 1;
            }
        } else if let Some(v) = a.strip_prefix("--kubeconfig=") {
            seg.kubeconfig = Some(v.to_string());
        } else if a == "-n" || a == "--namespace" {
            if let Some(v) = next {
                seg.k8s_namespace = Some(v);
                i += 1;
            }
        } else if let Some(v) = a
            .strip_prefix("--namespace=")
            .or_else(|| a.strip_prefix("-n="))
        {
            seg.k8s_namespace = Some(v.to_string());
        }
        i += 1;
    }
    // `kubectl delete ns prod`: the namespace being deleted is the target.
    if let [verb, kind, name, ..] = positional.as_slice() {
        if *verb == "delete" && matches!(kind.as_str(), "ns" | "namespace" | "namespaces") {
            seg.k8s_namespace = Some((*name).clone());
        }
    }
    if let Some(ctx) = explicit_ctx {
        // `--context $c` / `--context "$(…)"`: resolved from the line, or
        // unknown. A run-time value (`{}` of xargs, `$(…)` output, a loop
        // over `get-contexts`) is never a known context.
        let mut values = expand_line_value(&ctx, state);
        let placeholder = values.iter().any(|v| !is_literal_name(v)) || !is_literal_name(&ctx);
        values.retain(|v| is_literal_name(v));
        if placeholder && values.is_empty() && state.lists_contexts {
            seg.k8s_all_contexts = true;
        }
        match values.as_slice() {
            [] => {
                seg.k8s_context = None;
                seg.k8s_context_unknown = true;
            }
            [one] => {
                seg.k8s_context = Some(one.clone());
                seg.k8s_context_unknown = false;
            }
            [first, rest @ ..] => {
                seg.k8s_context = Some(first.clone());
                seg.k8s_context_unknown = false;
                seg.k8s_fallbacks = rest.iter().cloned().map(CtxAlt::Named).collect();
                seg.k8s_fallbacks_always = true;
                seg.k8s_context_list = true;
            }
        }
    } else if seg.place != Place::Pod {
        seg.k8s_context.clone_from(&state.k8s_context);
        seg.k8s_context_unknown = state.k8s_unknown;
        if !state.k8s_fallbacks.is_empty() {
            seg.k8s_fallbacks.clone_from(&state.k8s_fallbacks);
            seg.k8s_fallbacks_always = !state.k8s_switch_certain;
        }
    }
}

/// The possible values of a word written in the line: itself when literal;
/// for `$v` / `${v}` / `"$v"` the values the line assigned (`v=x`,
/// `for v in a b`); `$(echo x)` → `x`. Empty when the value is unknown.
fn expand_line_value(word: &str, state: &LineState) -> Vec<String> {
    let w = word.trim_matches('"');
    if let Some(inner) = w.strip_prefix("$(").and_then(|r| r.strip_suffix(')')) {
        let parts: Vec<&str> = inner.split_whitespace().collect();
        return match parts.as_slice() {
            ["echo" | "printf", x] => vec![(*x).trim_matches(['\'', '"']).to_string()],
            _ => Vec::new(),
        };
    }
    // `${CTX:-prod-eu}` / `${b:=$1}`: the variable's values, else the
    // default.
    if let Some((name, default)) = w
        .strip_prefix("${")
        .and_then(|r| r.strip_suffix('}'))
        .and_then(|r| {
            r.split_once(":-")
                .or_else(|| r.split_once(":="))
                .or_else(|| r.split_once('-'))
                .or_else(|| r.split_once('='))
        })
    {
        if let Some(v) = state.vars.get(name) {
            return v.clone();
        }
        if let Some((_, Some(v))) = state.env.iter().rev().find(|(k, _)| k == name) {
            return vec![v.clone()];
        }
        return if default.contains(['$', '`']) {
            Vec::new()
        } else {
            vec![default.to_string()]
        };
    }
    if let Some(name) = w
        .strip_prefix("${")
        .and_then(|r| r.strip_suffix('}'))
        .or_else(|| w.strip_prefix('$'))
    {
        if let Some(v) = state.vars.get(name) {
            return v.clone();
        }
        if let Some((_, Some(v))) = state.env.iter().rev().find(|(k, _)| k == name) {
            return vec![v.clone()];
        }
        return Vec::new();
    }
    if w.contains('$') || w.contains('`') {
        return Vec::new();
    }
    vec![w.to_string()]
}

/// Normalise a ref name: strip `refs/heads/`. Returns `None` for tags and
/// other non-branch refs.
fn branch_from_ref(r: &str) -> Option<String> {
    if r.is_empty() || r.starts_with("refs/tags/") {
        return None;
    }
    if let Some(b) = r.strip_prefix("refs/heads/") {
        return Some(b.to_string());
    }
    if r.starts_with("refs/") {
        return None;
    }
    Some(r.to_string())
}

fn parse_git(args: &[String], seg: &mut SegmentTargets, state: &mut LineState) {
    seg.git = true;
    let mut i = 0;
    // Global options before the verb.
    while let Some(a) = args.get(i) {
        if !a.starts_with('-') {
            break;
        }
        if matches!(
            a.as_str(),
            "-C" | "-c" | "--git-dir" | "--work-tree" | "--namespace" | "--config-env"
        ) {
            i += 2;
        } else {
            i += 1;
        }
    }
    let Some(verb) = args.get(i) else {
        seg.git_uses_current = true;
        return;
    };
    let rest = &args[i + 1..];
    match verb.as_str() {
        "push" => parse_git_push(rest, seg, state),
        "branch" => parse_git_branch(rest, seg),
        "checkout" | "switch" => parse_git_switch(rest, seg, state),
        // Moving the branch tip to another commit rewrites its history.
        "reset" if reset_moves_branch(rest) => {
            seg.git_uses_current = true;
            seg.git_reset_to = rest.iter().find(|a| !a.starts_with('-')).cloned();
        }
        // History rewriting of the current branch.
        "filter-branch" | "filter-repo" | "update-ref" => seg.git_uses_current = true,
        // A rebase rewrites the commits of the checked-out branch (`git
        // rebase -i HEAD~3` on main); continuing / aborting one does not
        // start a rewrite.
        "rebase"
            if !rest.iter().any(|a| {
                matches!(
                    a.as_str(),
                    "--abort"
                        | "--continue"
                        | "--skip"
                        | "--quit"
                        | "--edit-todo"
                        | "--show-current-patch"
                )
            }) =>
        {
            seg.git_uses_current = true;
        }
        // Everything else (cherry-pick, stash, gc, worktree,
        // checkout -- file, clean, ...) is local work that neither pushes,
        // rewrites nor deletes the protected branch: the checked-out branch
        // does not escalate it.
        _ => {}
    }
}

/// `git reset [--hard|--soft|...] <commit>` with a commit other than `HEAD`
/// moves the branch tip (drops commits).
fn reset_moves_branch(args: &[String]) -> bool {
    for a in args {
        if a == "--" {
            return false;
        }
        if a.starts_with('-') {
            continue;
        }
        return a != "HEAD" && a != "@";
    }
    false
}

/// `git checkout B` / `git switch B` (also `-b|-c|-C new`): later git
/// commands on the line run on `B`. `git checkout -- file` / `git checkout
/// .` do not switch. `git checkout -B main <start>` / `git switch -C main
/// <start>` reset an existing `main` to `<start>`: `main` is a target.
fn parse_git_switch(args: &[String], seg: &mut SegmentTargets, state: &mut LineState) {
    if args.iter().any(|a| a == "--") {
        return;
    }
    let mut i = 0;
    let mut target: Option<&String> = None;
    let mut reset = false;
    while i < args.len() {
        let a = &args[i];
        if matches!(a.as_str(), "-b" | "-B" | "-c" | "-C" | "--orphan") {
            reset = matches!(a.as_str(), "-B" | "-C");
            target = args.get(i + 1);
            break;
        }
        if !a.starts_with('-') {
            target = Some(a);
            break;
        }
        i += 1;
    }
    let creates = args
        .iter()
        .any(|a| matches!(a.as_str(), "-b" | "-B" | "-c" | "-C" | "--orphan"));
    if let Some(t) = target {
        if t != "-" && !t.starts_with('.') && !t.starts_with('/') {
            if reset && !seg.git_targets.contains(t) {
                seg.git_targets.push(t.clone());
            }
            state.git_branch = Some(t.clone());
            state.git_switch_creates = creates;
        }
    }
}

fn parse_git_push(args: &[String], seg: &mut SegmentTargets, state: &LineState) {
    let mut positionals: Vec<&str> = Vec::new();
    let mut delete = false;
    let mut i = 0;
    while i < args.len() {
        let a = args[i].as_str();
        if a == "--" {
            positionals.extend(args[i + 1..].iter().map(String::as_str));
            break;
        }
        if a.starts_with("--") {
            match a {
                "--all" | "--branches" | "--mirror" => seg.git_push_all = true,
                "--delete" => delete = true,
                _ if a.starts_with("--force-with-lease") || a == "--force-if-includes" => {
                    seg.git_force_lease = true;
                }
                "--push-option" | "--repo" | "--receive-pack" | "--exec" => i += 1,
                _ => {}
            }
        } else if a.starts_with('-') && a.len() > 1 {
            if a == "-o" {
                i += 1;
            } else if a[1..].contains('d') {
                delete = true;
            }
        } else {
            positionals.push(a);
        }
        i += 1;
    }

    // `git push --dry-run` / `-n`: nothing changes on the remote.
    if args.iter().any(|a| {
        a == "--dry-run" || (a.starts_with('-') && !a.starts_with("--") && a[1..].contains('n'))
    }) {
        seg.git_force_lease = false;
        return;
    }
    let refspecs = positionals.get(1..).unwrap_or(&[]);
    if refspecs.is_empty() {
        if !seg.git_push_all {
            // `git push` / `git push origin` pushes the current branch.
            seg.git_uses_current = true;
        }
        return;
    }
    for spec in refspecs {
        let spec = spec.strip_prefix('+').unwrap_or(spec);
        let dst = if delete {
            spec
        } else {
            refspec_colon(spec).map_or(spec, |at| &spec[at + 1..])
        };
        if dst == "HEAD" || dst == "@" || names_current_branch(dst) {
            seg.git_uses_current = true;
            continue;
        }
        if dst.contains(['$', '`']) || dst.contains("{}") {
            // A variable, a loop value or command output: its values when
            // the line sets them, else unknown.
            let mut values = if dst.contains("{}") {
                Vec::new()
            } else {
                expand_line_value(dst, state)
            };
            // `B=$(git branch --show-current); … origin $B`.
            let before = values.len();
            values.retain(|v| !names_current_branch(v));
            let current = values.len() < before;
            if current {
                seg.git_uses_current = true;
            }
            values.retain(|v| !v.contains(['$', '`']) && !v.contains("{}"));
            if values.is_empty() && !current {
                seg.git_target_unknown = true;
            }
            for v in values {
                if v == "HEAD" || v == "@" {
                    seg.git_uses_current = true;
                } else if let Some(b) = branch_from_ref(&v) {
                    if !seg.git_targets.contains(&b) {
                        seg.git_targets.push(b);
                    }
                }
            }
            continue;
        }
        if let Some(b) = branch_from_ref(dst) {
            if !seg.git_targets.contains(&b) {
                seg.git_targets.push(b);
            }
        }
    }
}

/// The position of the `src:dst` colon of a push refspec: the last `:`
/// outside `${…}` / `$(…)` (`"${b:=$1}"` is one destination).
fn refspec_colon(spec: &str) -> Option<usize> {
    let mut depth = 0usize;
    let mut at = None;
    let bytes = spec.as_bytes();
    for (i, b) in bytes.iter().enumerate() {
        match b {
            b'{' | b'(' if i > 0 && bytes[i - 1] == b'$' => depth += 1,
            b'}' | b')' => depth = depth.saturating_sub(1),
            b':' if depth == 0 => at = Some(i),
            _ => {}
        }
    }
    at
}

/// Whether a push destination is a command substitution printing the
/// checked-out branch (`$(git branch --show-current)`, `$(git rev-parse
/// --abbrev-ref HEAD)`, `` `git symbolic-ref --short HEAD` ``, oh-my-zsh's
/// `$(git_current_branch)`).
fn names_current_branch(dst: &str) -> bool {
    let d = dst.trim_matches('"');
    let Some(inner) = d
        .strip_prefix("$(")
        .and_then(|r| r.strip_suffix(')'))
        .or_else(|| d.strip_prefix('`').and_then(|r| r.strip_suffix('`')))
    else {
        return false;
    };
    let words: Vec<&str> = inner.split_whitespace().collect();
    let words = match words.as_slice() {
        ["command", rest @ ..] => rest,
        w => w,
    };
    matches!(
        words,
        // oh-my-zsh's helpers (`ggfl`, `ggpush`, `gpsup`): they print the
        // checked-out branch.
        ["git_current_branch" | "current_branch"]
            | ["git", "branch", "--show-current"]
            | ["git", "rev-parse", "--abbrev-ref", "HEAD" | "@"]
            | ["git", "symbolic-ref", "--short", "HEAD"]
            | ["git", "symbolic-ref", "--short", "-q", "HEAD"]
            | ["git", "name-rev", "--name-only", "HEAD"]
    )
}

fn parse_git_branch(args: &[String], seg: &mut SegmentTargets) {
    let mut positionals: Vec<&str> = Vec::new();
    let mut delete = false;
    let mut mv = false;
    let mut force = false;
    let mut i = 0;
    while i < args.len() {
        let a = args[i].as_str();
        if a.starts_with("--") {
            match a {
                "--delete" => delete = true,
                "--move" | "--copy" => mv = true,
                "--force" => force = true,
                "--set-upstream-to" | "--contains" | "--no-contains" | "--merged"
                | "--no-merged" | "--points-at" | "--format" | "--sort" => i += 1,
                _ => {}
            }
        } else if a.starts_with('-') && a.len() > 1 {
            let flags = &a[1..];
            if flags.contains('d') || flags.contains('D') {
                delete = true;
            }
            if flags.contains('m')
                || flags.contains('M')
                || flags.contains('c')
                || flags.contains('C')
            {
                mv = true;
            }
            if flags.contains('f')
                || flags.contains('D')
                || flags.contains('M')
                || flags.contains('C')
            {
                force = true;
            }
            if a == "-u" {
                i += 1;
            }
        } else {
            positionals.push(a);
        }
        i += 1;
    }

    let mut push = |name: &str| {
        if let Some(b) = branch_from_ref(name) {
            if !seg.git_targets.contains(&b) {
                seg.git_targets.push(b);
            }
        }
    };
    if delete {
        for p in &positionals {
            push(p);
        }
    } else if mv {
        // `git branch -m new` renames the current branch.
        let single = positionals.len() == 1;
        for p in &positionals {
            push(p);
        }
        if single {
            seg.git_uses_current = true;
        }
    } else if force {
        // `git branch -f main <commit>` resets `main`.
        if let Some(first) = positionals.first() {
            push(first);
        }
    }
    // Plain `git branch` / `git branch new-name` doesn't touch an existing
    // branch: no target, and the current branch is irrelevant.
}

/// Directories a command line acts on besides the current one.
///
/// Used for policy discovery: `cd` / `pushd` targets (cumulative: `cd a && cd b` → `a/b`),
/// `git -C DIR`, `git --git-dir DIR` / `GIT_DIR=DIR` (its repository),
/// `git --work-tree DIR`, `terraform|tofu -chdir=DIR` and `make -C DIR`.
/// Relative paths are relative to the current directory.
#[must_use]
#[allow(clippy::too_many_lines)]
pub fn command_target_dirs(command: &str) -> Vec<PathBuf> {
    let mut out: Vec<PathBuf> = Vec::new();
    let mut seen: std::collections::HashSet<PathBuf> = std::collections::HashSet::new();
    let mut cwd: Option<PathBuf> = None;
    // Bounded: a long `cd a && cd a && …` chain must stay linear (each
    // directory is looked up by policy discovery).
    let push =
        |out: &mut Vec<PathBuf>, seen: &mut std::collections::HashSet<PathBuf>, p: PathBuf| {
            if out.len() < MAX_TARGET_DIRS && seen.insert(p.clone()) {
                out.push(p);
            }
        };
    let rel = |cwd: &Option<PathBuf>, d: &str| -> PathBuf {
        let p = PathBuf::from(d);
        // Joined with `/` (shell syntax), not the platform separator: on
        // Windows `Path::join` adds `\`, which `normalize_path` does not
        // split, so `a/../b` would stay unresolved. `/x` is absolute in the
        // command even where `Path::is_absolute` wants a drive letter.
        let joined = if p.is_absolute() || d.starts_with('~') || d.starts_with('/') {
            p
        } else {
            cwd.as_ref().map_or_else(
                || p.clone(),
                |c| PathBuf::from(format!("{}/{d}", c.display())),
            )
        };
        // Lexically normalized (`a/../b` → `b`), and unknown past a length.
        let n = PathBuf::from(crate::parser::normalize_path(&joined.display().to_string()));
        if n.as_os_str().len() > MAX_TARGET_DIR_LEN {
            PathBuf::new()
        } else {
            n
        }
    };
    for seg in tokenize_segments(command) {
        let mut i = 0;
        while let Some(t) = seg.get(i) {
            if let Some((k, v)) = is_assignment(t) {
                if k == "GIT_DIR" || k == "GIT_WORK_TREE" {
                    let p = rel(&cwd, &v);
                    push(&mut out, &mut seen, p);
                }
                i += 1;
            } else if matches!(
                program_name(t),
                "sudo" | "env" | "command" | "builtin" | "time" | "nohup"
            ) {
                let is_env = program_name(t) == "env";
                i += 1;
                while let Some(a) = seg.get(i).filter(|a| a.starts_with('-')) {
                    // `env -C DIR cmd` / `env --chdir=DIR cmd` runs in DIR.
                    let dir = if is_env && (a == "-C" || a == "--chdir") {
                        i += 1;
                        seg.get(i).cloned()
                    } else if is_env {
                        a.strip_prefix("--chdir=").map(str::to_string)
                    } else {
                        None
                    };
                    if let Some(d) = dir {
                        let p = rel(&cwd, &d);
                        push(&mut out, &mut seen, p);
                    }
                    i += 1;
                }
            } else {
                break;
            }
        }
        let Some(prog_tok) = seg.get(i) else {
            continue;
        };
        // A script run by its absolute path acts in its own repository.
        if prog_tok.starts_with('/') {
            if let Some(parent) = std::path::Path::new(prog_tok).parent() {
                push(&mut out, &mut seen, parent.to_path_buf());
            }
        }
        let prog = program_name(prog_tok);
        let args = &seg[i + 1..];
        match prog {
            "cd" | "pushd" => {
                if let Some(d) = args
                    .iter()
                    .find(|a| !a.starts_with('-') && !a.starts_with('+'))
                {
                    let p = rel(&cwd, d);
                    if p.as_os_str().is_empty() {
                        cwd = None;
                    } else {
                        push(&mut out, &mut seen, p.clone());
                        cwd = Some(p);
                    }
                }
            }
            "git" => {
                let mut k = 0;
                while let Some(a) = args.get(k) {
                    if !a.starts_with('-') {
                        break;
                    }
                    let value = match a.as_str() {
                        "-C" | "--git-dir" | "--work-tree" => {
                            k += 1;
                            args.get(k).cloned()
                        }
                        _ => a
                            .strip_prefix("--git-dir=")
                            .or_else(|| a.strip_prefix("--work-tree="))
                            .map(str::to_string),
                    };
                    if let Some(v) = value {
                        let p = rel(&cwd, &v);
                        push(&mut out, &mut seen, p);
                    }
                    if a == "-c" || a == "--namespace" || a == "--config-env" {
                        k += 1;
                    }
                    k += 1;
                }
            }
            "terraform" | "tofu" | "terragrunt" => {
                for a in args {
                    if let Some(v) = a
                        .strip_prefix("-chdir=")
                        .or_else(|| a.strip_prefix("--chdir="))
                    {
                        let p = rel(&cwd, v);
                        push(&mut out, &mut seen, p);
                    }
                }
            }
            "make" | "gmake" => {
                let mut k = 0;
                while let Some(a) = args.get(k) {
                    let value = if a == "-C" || a == "--directory" {
                        k += 1;
                        args.get(k).cloned()
                    } else {
                        a.strip_prefix("--directory=").map(str::to_string)
                    };
                    if let Some(v) = value {
                        let p = rel(&cwd, &v);
                        push(&mut out, &mut seen, p);
                    }
                    k += 1;
                }
            }
            _ => {}
        }
    }
    out
}

/// The directory `command` acts in when that is not `cwd`.
///
/// That is the directory of the first local git command that works elsewhere (`git -C repo …`,
/// `cd repo && git …`), else the first [`command_target_dirs`] entry (`cd
/// repo && make`, `make -C dir`). Absolute (relative to `cwd`, `~` is
/// `home`); `None` when the line names no other directory.
///
/// The audit log records the repository and branch of this directory.
#[must_use]
pub fn command_work_dir(
    command: &str,
    cwd: &std::path::Path,
    home: Option<&std::path::Path>,
) -> Option<PathBuf> {
    let targets = parse_command_targets(command);
    let dir = targets
        .segments
        .iter()
        .filter(|s| s.place == Place::Local)
        .find_map(|s| s.git_dir.clone())
        .or_else(|| {
            command_target_dirs(command)
                .into_iter()
                .find(|d| !d.as_os_str().is_empty())
                .map(|d| d.display().to_string())
        })?;
    let rest = dir
        .strip_prefix("~/")
        .or_else(|| dir.strip_prefix("$HOME/"))
        .or_else(|| dir.strip_prefix("${HOME}/"));
    let path = match (rest, home) {
        (Some(rest), Some(h)) => h.join(rest),
        _ if dir == "~" => home?.to_path_buf(),
        _ => PathBuf::from(&dir),
    };
    // An unexpanded `~user` is unknown. A `~` later in the path is a
    // literal character (`backup~1`, Windows short names like `RUNNER~1`).
    let text = path.to_string_lossy();
    if text.is_empty() || text.starts_with('~') || text.contains(['$', '`']) {
        return None;
    }
    let abs = if path.is_absolute() {
        path
    } else {
        cwd.join(path)
    };
    Some(PathBuf::from(crate::parser::normalize_path(
        &abs.display().to_string(),
    )))
}

/// Most directories [`command_target_dirs`] reports for one line.
const MAX_TARGET_DIRS: usize = 64;

/// Longest directory [`command_target_dirs`] tracks (longer is unknown).
const MAX_TARGET_DIR_LEN: usize = 4096;

/// Split a command line into segments (on `;`, `&`, `|`, newlines and
/// parentheses) of shell-like tokens. Quotes are removed from tokens; quoted
/// text stays inside a single token. A backtick substitution is its own
/// segment and a `$(…)` word of the command around it. `#` comments are
/// dropped. This is deliberately small: it only feeds context detection.
fn tokenize_segments(command: &str) -> Vec<Vec<String>> {
    tokenize_segments_with_ops(command)
        .into_iter()
        .map(|(s, _)| s)
        .collect()
}

/// [`tokenize_segments`] with, for each segment, the operator that follows
/// it (`;`, `&&`, `||`, `|`, `&`, newline, a parenthesis, or empty at the
/// end).
fn tokenize_segments_with_ops(command: &str) -> Vec<(Vec<String>, String)> {
    tokenize_segments_at(command, 0)
}

/// Deepest `$( … )` / backtick nesting [`tokenize_segments_with_ops`]
/// splits into commands of their own. Deeper bodies stay one word of the
/// command around them (the parser reports such a line as too deeply
/// nested), so a crafted line cannot exhaust the stack or cost quadratic
/// time.
const MAX_TOKENIZE_DEPTH: usize = 32;

/// [`tokenize_segments_with_ops`] at substitution nesting `level`.
#[allow(clippy::too_many_lines)]
fn tokenize_segments_at(command: &str, level: usize) -> Vec<(Vec<String>, String)> {
    let nested = level < MAX_TOKENIZE_DEPTH;
    let mut segments: Vec<(Vec<String>, String)> = Vec::new();
    let mut current: Vec<String> = Vec::new();
    let mut tok = String::new();
    let mut in_tok = false;
    let mut chars = command.chars().peekable();

    let flush_tok = |tok: &mut String, in_tok: &mut bool, current: &mut Vec<String>| {
        if *in_tok {
            current.push(std::mem::take(tok));
            *in_tok = false;
        }
    };

    while let Some(c) = chars.next() {
        match c {
            '\'' => {
                in_tok = true;
                for n in chars.by_ref() {
                    if n == '\'' {
                        break;
                    }
                    tok.push(n);
                }
            }
            '"' => {
                in_tok = true;
                while let Some(n) = chars.next() {
                    match n {
                        '"' => break,
                        '\\' => {
                            if let Some(&esc) = chars.peek() {
                                if matches!(esc, '"' | '\\' | '$' | '`') {
                                    tok.push(esc);
                                    chars.next();
                                    continue;
                                }
                            }
                            tok.push('\\');
                        }
                        _ => tok.push(n),
                    }
                }
            }
            '\\' => {
                in_tok = true;
                if let Some(n) = chars.next() {
                    if n != '\n' {
                        tok.push(n);
                    }
                }
            }
            '#' if !in_tok && crate::parser::hash_comments() => {
                for n in chars.by_ref() {
                    if n == '\n' {
                        break;
                    }
                }
                flush_tok(&mut tok, &mut in_tok, &mut current);
                segments.push((std::mem::take(&mut current), "\n".to_string()));
            }
            // `$(cmd)` (unquoted): like a backtick, its own command and one
            // word of this one (`git push -f origin $(git branch
            // --show-current)` pushes the current branch). `$((…))` is
            // arithmetic: one word.
            '$' if chars.peek() == Some(&'(') => {
                chars.next();
                let mut body = String::new();
                let mut depth = 1usize;
                let mut quote: Option<char> = None;
                for n in chars.by_ref() {
                    match (quote, n) {
                        (Some(q), _) if n == q => quote = None,
                        (None, '\'' | '"') => quote = Some(n),
                        (None, '(') => depth += 1,
                        (None, ')') => {
                            depth -= 1;
                            if depth == 0 {
                                break;
                            }
                        }
                        _ => {}
                    }
                    body.push(n);
                }
                if nested && !body.starts_with('(') {
                    segments.extend(tokenize_segments_at(&body, level + 1));
                }
                tok.push_str("$(");
                tok.push_str(body.trim());
                tok.push(')');
                in_tok = true;
            }
            // `` `cmd` ``: its own command, and one word (its output) of
            // this one (`git reset --hard `git rev-parse HEAD~1``).
            '`' => {
                let mut body = String::new();
                while let Some(n) = chars.next() {
                    match n {
                        '`' => break,
                        '\\' => {
                            if let Some(e) = chars.next() {
                                body.push(e);
                            }
                        }
                        _ => body.push(n),
                    }
                }
                if nested {
                    segments.extend(tokenize_segments_at(&body, level + 1));
                }
                tok.push_str("$(");
                tok.push_str(body.trim());
                tok.push(')');
                in_tok = true;
            }
            // Redirections: `2>&1`, `>&2`, `&>/dev/null`, `&>>log` are not
            // operators.
            '&' if (in_tok && tok.ends_with(['>', '<'])) || matches!(chars.peek(), Some('>')) => {
                in_tok = true;
                tok.push(c);
            }
            '|' if in_tok && tok.ends_with('>') => {
                // `>|` (clobber).
                tok.push(c);
            }
            ';' | '&' | '|' | '\n' | '(' | ')' => {
                flush_tok(&mut tok, &mut in_tok, &mut current);
                let mut op = c.to_string();
                if matches!(c, '&' | '|') && chars.peek() == Some(&c) {
                    chars.next();
                    op.push(c);
                }
                if !current.is_empty() {
                    segments.push((std::mem::take(&mut current), op));
                } else if let Some(last) = segments.last_mut() {
                    // `(kubectx dev) && …`: the operator after the group.
                    if last.1 == ")" {
                        last.1 = op;
                    }
                }
            }
            c if c.is_whitespace() => flush_tok(&mut tok, &mut in_tok, &mut current),
            _ => {
                in_tok = true;
                tok.push(c);
            }
        }
    }
    flush_tok(&mut tok, &mut in_tok, &mut current);
    if !current.is_empty() {
        segments.push((current, String::new()));
    }
    for (s, _) in &mut segments {
        drop_redirections(s);
        normalize_command_word(s);
    }
    segments.retain(|(s, _)| !s.is_empty());
    segments
}

/// The length of the redirection operator a token starts with (`2>&1`,
/// `>/dev/null`, `&>log`, `<<<x`, `>|f`), if it is one.
fn redirection_op_len(tok: &str) -> Option<usize> {
    let digits = tok.len() - tok.trim_start_matches(|c: char| c.is_ascii_digit()).len();
    let rest = &tok[digits..];
    let ops = [
        "&>>", "&>", ">>", ">&", ">|", "<<<", "<<-", "<<", "<&", "<>", ">", "<",
    ];
    let op = ops.iter().find(|o| rest.starts_with(**o))?;
    // `<(…)` / `>(…)`: a process substitution, not a redirection.
    (!rest[op.len()..].starts_with('(')).then_some(digits + op.len())
}

/// Remove redirections and their targets (`2>&1`, `> /dev/null`, `&>log`,
/// `</dev/null`): they are not arguments of the command (`git reset --hard
/// 2>&1` resets to `HEAD`, not to `2>&1`).
fn drop_redirections(tokens: &mut Vec<String>) {
    let mut out = Vec::with_capacity(tokens.len());
    let mut it = std::mem::take(tokens).into_iter();
    while let Some(t) = it.next() {
        match redirection_op_len(&t) {
            // The target is the next word (`> /dev/null`).
            Some(n) if n == t.len() => {
                it.next();
            }
            Some(_) => {}
            None => out.push(t),
        }
    }
    *tokens = out;
}

/// zsh spellings of the command word: a brace group glued to it
/// (`{git push -f;}`) and `=cmd` (the path of `cmd`).
fn normalize_command_word(tokens: &mut Vec<String>) {
    // The command word follows compound-command keywords (`then {git …;}`).
    let at = tokens
        .iter()
        .position(|t| {
            !matches!(
                t.as_str(),
                "if" | "then" | "else" | "elif" | "do" | "while" | "until" | "!" | "{" | "time"
            )
        })
        .unwrap_or(0);
    if let Some(first) = tokens.get_mut(at) {
        if first.len() > 1 && first.starts_with('{') && first != "{}" {
            first.remove(0);
        }
        if first.len() > 1
            && first.starts_with('=')
            && first[1..].starts_with(|c: char| c.is_ascii_alphanumeric() || c == '/')
        {
            first.remove(0);
        }
    }
    // A glued closing brace (`--hard;}` is split at `;`, leaving `}`).
    if tokens.last().is_some_and(|t| t == "}") {
        tokens.pop();
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::env::MockEnvironment;
    use std::collections::HashMap;

    fn default_config() -> ContextConfig {
        ContextConfig::default()
    }

    fn env_with_branch(branch: &str) -> MockEnvironment {
        let mut cmd_outputs = HashMap::new();
        cmd_outputs.insert("git rev-parse --abbrev-ref HEAD".into(), branch.into());
        MockEnvironment {
            command_outputs: cmd_outputs,
            cwd: "/repo".into(),
            ..Default::default()
        }
    }

    fn env_with_k8s(ctx: &str) -> MockEnvironment {
        let mut cmd_outputs = HashMap::new();
        cmd_outputs.insert("kubectl config current-context".into(), ctx.into());
        MockEnvironment {
            command_outputs: cmd_outputs,
            cwd: "/app".into(),
            ..Default::default()
        }
    }

    #[test]
    fn test_detect_normal_context() {
        let env = MockEnvironment {
            cwd: "/Users/dev/project".into(),
            ..Default::default()
        };
        let ctx = detect(&env, &default_config());
        assert_eq!(ctx.risk_level, RiskLevel::Normal);
        assert!(!ctx.is_ssh);
        assert!(!ctx.is_root);
    }

    #[test]
    fn test_detect_ssh_session() {
        let mut env_vars = HashMap::new();
        env_vars.insert("SSH_CONNECTION".into(), "10.0.0.1 22 10.0.0.2 54321".into());
        let env = MockEnvironment {
            env_vars,
            cwd: "/home/user".into(),
            ..Default::default()
        };
        let ctx = detect(&env, &default_config());
        assert!(ctx.is_ssh);
        assert_eq!(ctx.risk_level, RiskLevel::Elevated);
    }

    #[test]
    fn test_empty_ssh_connection_is_not_ssh() {
        let mut env_vars = HashMap::new();
        env_vars.insert("SSH_CONNECTION".into(), String::new());
        let env = MockEnvironment {
            env_vars,
            ..Default::default()
        };
        assert!(!detect(&env, &default_config()).is_ssh);
    }

    #[test]
    fn test_detect_root_user_via_euid() {
        let env = MockEnvironment {
            euid: Some(0),
            cwd: "/root".into(),
            ..Default::default()
        };
        let ctx = detect(&env, &default_config());
        assert!(ctx.is_root);
        assert!(!ctx.root_via_sudo);
        assert_eq!(ctx.risk_level, RiskLevel::Critical);
        assert!(ctx.labels.contains(&"root=true".to_string()));
    }

    #[test]
    fn test_euid_env_var_is_not_trusted() {
        // `$EUID` is a non-exported shell variable; it must not be used.
        let mut env_vars = HashMap::new();
        env_vars.insert("EUID".into(), "0".into());
        let env = MockEnvironment {
            env_vars,
            euid: Some(1000),
            ..Default::default()
        };
        let ctx = detect(&env, &default_config());
        assert!(!ctx.is_root);
    }

    #[test]
    fn test_non_root_uid() {
        let env = MockEnvironment {
            euid: Some(501),
            ..Default::default()
        };
        assert!(!detect(&env, &default_config()).is_root);
    }

    #[test]
    fn test_real_environment_euid_matches_libc() {
        let env = crate::env::RealEnvironment;
        #[cfg(unix)]
        assert_eq!(env.effective_uid(), Some(unsafe { libc::geteuid() }));
    }

    #[test]
    fn test_sudo_prefix_is_root() {
        let env = MockEnvironment::default();
        let ctx = detect_for_command(&env, &default_config(), "sudo rm -rf /var/lib/x");
        assert!(ctx.is_root);
        assert!(ctx.root_via_sudo);
        assert_eq!(ctx.risk_level, RiskLevel::Critical);
        let ctx = detect_for_command(&env, &default_config(), "sudo -u bob rm -rf /tmp/x");
        assert!(!ctx.is_root);
    }

    #[test]
    fn test_detect_protected_branch() {
        let env = env_with_branch("main");
        let ctx = detect(&env, &default_config());
        assert_eq!(ctx.git_branch, Some("main".into()));
        assert_eq!(ctx.risk_level, RiskLevel::Critical);
    }

    #[test]
    fn test_detect_production_k8s() {
        let env = env_with_k8s("prod-us-east-1");
        let ctx = detect(&env, &default_config());
        assert_eq!(ctx.k8s_context, Some("prod-us-east-1".into()));
        assert_eq!(ctx.risk_level, RiskLevel::Critical);
    }

    #[test]
    fn test_detect_production_env() {
        let mut env_vars = HashMap::new();
        env_vars.insert("NODE_ENV".into(), "production".into());
        let env = MockEnvironment {
            env_vars,
            cwd: "/app".into(),
            ..Default::default()
        };
        let ctx = detect(&env, &default_config());
        assert_eq!(ctx.risk_level, RiskLevel::Critical);
        assert_eq!(ctx.env_signals, vec!["NODE_ENV=production"]);
        assert!(ctx.labels.contains(&"env:NODE_ENV=production".to_string()));
    }

    #[test]
    fn test_inline_env_assignment_is_signal() {
        let env = MockEnvironment::default();
        let ctx = detect_for_command(
            &env,
            &default_config(),
            "NODE_ENV=production npm run migrate",
        );
        assert_eq!(ctx.env_signals, vec!["NODE_ENV=production"]);
        assert_eq!(ctx.risk_level, RiskLevel::Critical);
    }

    #[test]
    fn test_feature_branch_is_normal() {
        let env = env_with_branch("feature/my-thing");
        let ctx = detect(&env, &default_config());
        assert_eq!(ctx.risk_level, RiskLevel::Normal);
    }

    #[test]
    fn test_release_wildcard_branch() {
        let env = env_with_branch("release/v2.0");
        let ctx = detect(&env, &default_config());
        assert_eq!(ctx.risk_level, RiskLevel::Critical);
    }

    #[test]
    fn test_escalate_challenge_normal() {
        let esc = EscalationConfig::default();
        assert_eq!(
            escalate_challenge(&Challenge::Math, RiskLevel::Normal, &esc),
            Challenge::Math
        );
    }

    #[test]
    fn test_escalate_challenge_elevated() {
        let esc = EscalationConfig::default();
        assert_eq!(
            escalate_challenge(&Challenge::Enter, RiskLevel::Elevated, &esc),
            Challenge::Math
        );
        assert_eq!(
            escalate_challenge(&Challenge::Math, RiskLevel::Elevated, &esc),
            Challenge::Math
        );
    }

    #[test]
    fn test_escalate_challenge_critical() {
        let esc = EscalationConfig::default();
        assert_eq!(
            escalate_challenge(&Challenge::Math, RiskLevel::Critical, &esc),
            Challenge::Yes
        );
    }

    #[test]
    fn test_escalate_cannot_lower() {
        // Even a misconfigured floor (Enter) can't lower Yes or Math.
        let esc = EscalationConfig {
            elevated: Challenge::Enter,
            critical: Challenge::Enter,
        };
        for base in [Challenge::Enter, Challenge::Math, Challenge::Yes] {
            for risk in [RiskLevel::Normal, RiskLevel::Elevated, RiskLevel::Critical] {
                assert!(escalate_challenge(&base, risk, &esc) >= base);
            }
        }
    }

    // -----------------------------------------------------------------------
    // k8s segment matching
    // -----------------------------------------------------------------------

    #[test]
    fn test_k8s_segment_matching() {
        let p = default_production_k8s_patterns();
        for prod in [
            "prod",
            "PROD-EU",
            "prod-eu",
            "gke_acme_prod_euw1",
            "arn:aws:eks:us-east-1:123:cluster/prd-main",
            "acme.production.cluster",
            "foo-live",
            "user@prod",
        ] {
            assert!(matches_any_pattern(prod, &p), "{prod} should be production");
        }
        for non in [
            "preprod",
            "k8s-products-dev",
            "reproduce-bug",
            "olive-test",
            "delivery-dev",
            "minikube",
            "docker-desktop",
            "staging",
            "productive",
        ] {
            assert!(
                !matches_any_pattern(non, &p),
                "{non} should NOT be production"
            );
        }
    }

    #[test]
    fn test_k8s_multi_segment_and_glob_patterns() {
        let p = vec!["acme-eks".to_string()];
        assert!(matches_any_pattern("us-acme-eks-1", &p));
        assert!(!matches_any_pattern("acme-eksx", &p));
        let g = vec!["*prod*".to_string()];
        assert!(matches_any_pattern("preprod", &g));
        assert!(!matches_any_pattern("dev", &g));
    }

    #[test]
    fn test_glob_match() {
        assert!(glob_match(b"release/*", b"release/v1/x"));
        assert!(glob_match(b"a?c", b"abc"));
        assert!(!glob_match(b"a?c", b"ac"));
        assert!(glob_match(b"*", b""));
        assert!(!glob_match(b"main", b"mainx"));
    }

    // -----------------------------------------------------------------------
    // Command-aware k8s detection
    // -----------------------------------------------------------------------

    #[test]
    fn test_k8s_context_flag_overrides_current() {
        let env = env_with_k8s("dev");
        for cmd in [
            "kubectl --context prod-eu delete deploy api",
            "kubectl delete deploy api --context=prod-eu",
            "helm --kube-context prod-eu uninstall api",
            "k --context \"prod-eu\" delete ns payments",
        ] {
            let ctx = detect_for_command(&env, &default_config(), cmd);
            assert_eq!(ctx.k8s_context.as_deref(), Some("prod-eu"), "{cmd}");
            assert_eq!(ctx.risk_level, RiskLevel::Critical, "{cmd}");
        }
    }

    #[test]
    fn test_inline_kubeconfig_is_read() {
        let mut files = HashMap::new();
        files.insert(
            PathBuf::from("/home/me/.kube/prod"),
            "apiVersion: v1\ncurrent-context: prod-eu\nkind: Config\n".to_string(),
        );
        let mut env = env_with_k8s("dev");
        env.files = files;
        env.home = Some(PathBuf::from("/home/me"));
        let ctx = detect_for_command(
            &env,
            &default_config(),
            "KUBECONFIG=~/.kube/prod kubectl delete ns payments",
        );
        assert_eq!(ctx.k8s_context.as_deref(), Some("prod-eu"));
        let ctx = detect_for_command(
            &env,
            &default_config(),
            "kubectl --kubeconfig /home/me/.kube/prod delete ns payments",
        );
        assert_eq!(ctx.k8s_context.as_deref(), Some("prod-eu"));
    }

    #[test]
    fn test_kubeconfig_flag_falls_back_to_kubectl() {
        let mut env = env_with_k8s("dev");
        env.command_outputs.insert(
            "kubectl config current-context --kubeconfig /x/cfg".into(),
            "prd-1".into(),
        );
        // The file exists but does not name a context: ask kubectl.
        env.files.insert("/x/cfg".into(), "apiVersion: v1\n".into());
        let ctx = detect_for_command(
            &env,
            &default_config(),
            "kubectl --kubeconfig=/x/cfg delete ns a",
        );
        assert_eq!(ctx.k8s_context.as_deref(), Some("prd-1"));
    }

    #[test]
    fn test_kubectl_timeout_is_unknown_not_normal() {
        let mut env = MockEnvironment::default();
        env.timed_out_commands
            .insert("kubectl config current-context".into());
        let ctx = detect_for_command(&env, &default_config(), "kubectl delete deploy api");
        assert!(ctx.k8s_context.is_none());
        assert!(ctx.k8s_unknown);
        assert_eq!(ctx.risk_level, RiskLevel::Elevated);
        assert!(ctx.labels.contains(&"k8s=unknown".to_string()));
    }

    #[test]
    fn test_kubectl_timeout_falls_back_to_kubeconfig_file() {
        let mut env = MockEnvironment {
            home: Some(PathBuf::from("/h")),
            ..Default::default()
        };
        env.timed_out_commands
            .insert("kubectl config current-context".into());
        env.files.insert(
            PathBuf::from("/h/.kube/config"),
            "current-context: \"prod-eu\"\n".into(),
        );
        let ctx = detect_for_command(&env, &default_config(), "kubectl delete deploy api");
        assert_eq!(ctx.k8s_context.as_deref(), Some("prod-eu"));
        assert!(!ctx.k8s_unknown);
        assert_eq!(ctx.risk_level, RiskLevel::Critical);
    }

    #[test]
    fn test_kubectl_failure_is_no_context() {
        // kubectl missing / no current context set: genuinely no context.
        let env = MockEnvironment::default();
        let ctx = detect_for_command(&env, &default_config(), "kubectl delete deploy api");
        assert!(ctx.k8s_context.is_none());
        assert!(!ctx.k8s_unknown);
        assert_eq!(ctx.risk_level, RiskLevel::Normal);
    }

    #[test]
    fn test_non_k8s_command_skips_kubectl_probe() {
        let env = env_with_k8s("prod-eu");
        let ctx = detect_for_command(&env, &default_config(), "rm -rf ./build");
        assert!(ctx.k8s_context.is_none());
        // ...but `detect` without a command still probes it.
        assert!(detect(&env, &default_config()).k8s_context.is_some());
    }

    // -----------------------------------------------------------------------
    // Push target parsing
    // -----------------------------------------------------------------------

    fn targets(cmd: &str) -> CommandTargets {
        parse_command_targets(cmd)
    }

    #[test]
    fn test_push_targets() {
        for (cmd, expected) in [
            ("git push -f origin main", vec!["main"]),
            ("git push --force origin main", vec!["main"]),
            ("git push origin +main", vec!["main"]),
            ("git push --force origin HEAD:main", vec!["main"]),
            ("git push origin feature:refs/heads/main", vec!["main"]),
            ("git push --delete origin main", vec!["main"]),
            ("git push origin :main", vec!["main"]),
            ("git push -d origin release/1.0", vec!["release/1.0"]),
            ("git -C repo push -f origin main", vec!["main"]),
            ("git -c core.x=y push --force origin main", vec!["main"]),
            ("git push -o ci.skip origin main", vec!["main"]),
            (
                "git push --force-with-lease=main:abc origin main",
                vec!["main"],
            ),
            ("git push origin main dev", vec!["main", "dev"]),
            ("git push origin v1.0:refs/tags/v1.0", vec![]),
        ] {
            let t = targets(cmd);
            assert_eq!(t.git_targets, expected, "{cmd}");
        }
    }

    #[test]
    fn test_push_without_refspec_uses_current() {
        for cmd in [
            "git push -f",
            "git push --force origin",
            "git push origin HEAD",
        ] {
            let t = targets(cmd);
            assert!(t.git_uses_current, "{cmd}");
            assert!(t.git_targets.is_empty(), "{cmd}");
        }
        let t = targets("git push --mirror origin");
        assert!(t.git_push_all);
    }

    #[test]
    fn test_branch_delete_targets() {
        assert_eq!(targets("git branch -D main").git_targets, vec!["main"]);
        assert_eq!(
            targets("git branch --delete --force feature/x main").git_targets,
            vec!["feature/x", "main"]
        );
        assert_eq!(
            targets("git branch -f main HEAD~3").git_targets,
            vec!["main"]
        );
        assert!(targets("git branch new-thing").git_targets.is_empty());
        assert!(!targets("git branch -D feature").git_uses_current);
    }

    #[test]
    fn test_push_target_main_from_feature_branch_is_critical() {
        let env = env_with_branch("feature/login");
        let ctx = detect_for_command(&env, &default_config(), "git push -f origin main");
        assert_eq!(ctx.risk_level, RiskLevel::Critical);
        assert!(ctx.labels.contains(&"target=main".to_string()));
        let ctx = detect_for_command(&env, &default_config(), "git push --force origin HEAD:main");
        assert_eq!(ctx.risk_level, RiskLevel::Critical);
        let ctx = detect_for_command(&env, &default_config(), "git branch -D main");
        assert_eq!(ctx.risk_level, RiskLevel::Critical);
    }

    #[test]
    fn test_push_feature_from_main_is_not_protected() {
        let env = env_with_branch("main");
        let ctx = detect_for_command(&env, &default_config(), "git push -f origin feature/login");
        assert_eq!(ctx.risk_level, RiskLevel::Normal);
        let ctx = detect_for_command(&env, &default_config(), "git branch -D feature/login");
        assert_eq!(ctx.risk_level, RiskLevel::Normal);
        // A bare push still pushes the current branch (main).
        let ctx = detect_for_command(&env, &default_config(), "git push -f");
        assert_eq!(ctx.risk_level, RiskLevel::Critical);
        // Moving the branch tip (dropping commits) rewrites main's history.
        let ctx = detect_for_command(&env, &default_config(), "git reset --hard HEAD~1");
        assert_eq!(ctx.risk_level, RiskLevel::Critical);
        // Discarding working-tree changes does not touch the branch.
        let ctx = detect_for_command(&env, &default_config(), "git reset --hard");
        assert_eq!(ctx.risk_level, RiskLevel::Normal);
    }

    #[test]
    fn test_local_only_git_commands_do_not_escalate_on_protected_branch() {
        let env = env_with_branch("main");
        for cmd in [
            "git cherry-pick abc123",
            "git rebase --continue",
            "git checkout -- README.md",
            "git worktree remove --force ../wt",
            "git stash clear",
            "git gc --prune=now",
            "git branch -d feature/login",
            "git clean -fdx",
        ] {
            let ctx = detect_for_command(&env, &default_config(), cmd);
            assert_eq!(ctx.risk_level, RiskLevel::Normal, "{cmd}: {ctx:?}");
            // The branch is still shown.
            assert!(ctx.labels.contains(&"branch=main".to_string()), "{cmd}");
        }
        for cmd in [
            "git push -f",
            "git push --force-with-lease",
            "git filter-branch --tree-filter x HEAD",
            // A rebase rewrites the commits of main.
            "git rebase -i HEAD~3",
            "git branch -D main",
            "git reset --hard origin/main~2",
        ] {
            let ctx = detect_for_command(&env, &default_config(), cmd);
            assert_eq!(ctx.risk_level, RiskLevel::Critical, "{cmd}: {ctx:?}");
        }
    }

    #[test]
    fn test_remote_git_command_ignores_local_branch() {
        let env = env_with_branch("main");
        let ctx = detect_for_command(&env, &default_config(), "ssh build-box git push -f");
        assert_eq!(ctx.risk_level, RiskLevel::Normal, "{ctx:?}");
        assert!(
            ctx.labels.contains(&"remote=build-box".to_string()),
            "{ctx:?}"
        );
    }

    #[test]
    fn test_git_branch_from_head_file_without_subprocess() {
        let mut env = MockEnvironment {
            cwd: "/repo/src".into(),
            ..Default::default()
        };
        env.files
            .insert("/repo/.git/HEAD".into(), "ref: refs/heads/main\n".into());
        let ctx = detect_for_command(
            &crate::env::NoContextEnvironment::new(&env),
            &default_config(),
            "git push -f",
        );
        assert_eq!(ctx.git_branch.as_deref(), Some("main"));
        assert_eq!(ctx.risk_level, RiskLevel::Critical);
        // A worktree's `.git` file points at the real HEAD.
        let mut env = MockEnvironment {
            cwd: "/wt".into(),
            ..Default::default()
        };
        env.files.insert(
            "/wt/.git".into(),
            "gitdir: /repo/.git/worktrees/wt\n".into(),
        );
        env.files.insert(
            "/repo/.git/worktrees/wt/HEAD".into(),
            "ref: refs/heads/release/1.0\n".into(),
        );
        let ctx = detect_for_command(&env, &default_config(), "git push -f");
        assert_eq!(ctx.git_branch.as_deref(), Some("release/1.0"));
    }

    #[test]
    fn test_git_timeout_is_unknown_not_normal() {
        let mut env = MockEnvironment {
            cwd: "/tmp/test".into(),
            ..Default::default()
        };
        env.timed_out_commands
            .insert("git rev-parse --abbrev-ref HEAD".into());
        let ctx = detect_for_command(&env, &default_config(), "git push -f");
        assert!(ctx.git_unknown);
        assert_eq!(ctx.risk_level, RiskLevel::Elevated);
        assert!(ctx.labels.contains(&"git=unknown".to_string()), "{ctx:?}");
        let reasons = ctx.risk_reasons(&default_config());
        assert!(reasons
            .iter()
            .any(|(_, r)| r.contains("git branch unknown")));
    }

    #[test]
    fn test_context_switch_earlier_in_line_applies() {
        let env = env_with_k8s("dev");
        for cmd in [
            "kubectl config use-context prod-eu && kubectl delete deploy api",
            "kubectx prod-eu; kubectl delete deploy api",
        ] {
            let ctx = detect_for_command(&env, &default_config(), cmd);
            assert_eq!(ctx.k8s_context.as_deref(), Some("prod-eu"), "{cmd}");
            assert_eq!(ctx.risk_level, RiskLevel::Critical, "{cmd}");
        }
        // `export KUBECONFIG=…;` points the next command at another file.
        let mut env = env_with_k8s("dev");
        env.files
            .insert("/kc/prod".into(), "current-context: prod-eu\n".into());
        let ctx = detect_for_command(
            &env,
            &default_config(),
            "export KUBECONFIG=/kc/prod; kubectl delete deploy api",
        );
        assert_eq!(ctx.k8s_context.as_deref(), Some("prod-eu"));
        // `git checkout main && git push -f` pushes main.
        let env = env_with_branch("feature/login");
        let ctx = detect_for_command(&env, &default_config(), "git checkout main && git push -f");
        assert_eq!(ctx.git_branch.as_deref(), Some("main"));
        assert!(ctx.git_branch_switched);
        assert_eq!(ctx.risk_level, RiskLevel::Critical);
        assert!(ctx.labels.iter().any(|l| l.contains("switched")), "{ctx:?}");
        // `export NODE_ENV=production;` applies to the next command.
        let env = MockEnvironment::default();
        let ctx = detect_for_command(
            &env,
            &default_config(),
            "export NODE_ENV=production; kubectl cordon n1",
        );
        assert_eq!(ctx.risk_level, RiskLevel::Critical);
    }

    #[test]
    fn test_cloud_and_iac_production_targets() {
        let env = MockEnvironment::default();
        let cfg = default_config();
        for (cmd, label) in [
            (
                "AWS_PROFILE=prod aws s3 rb s3://b --force",
                "aws-profile=prod",
            ),
            (
                "aws --profile production rds delete-db-instance x",
                "aws-profile=production",
            ),
            ("TF_WORKSPACE=prod terraform destroy", "tf-workspace=prod"),
            (
                "terraform workspace select prod; terraform destroy",
                "tf-workspace=prod",
            ),
            (
                "gcloud --project acme-prod sql instances delete db",
                "gcp-project=acme-prod",
            ),
            (
                "gcloud config set project acme-prod && gcloud sql instances delete db",
                "gcp-project=acme-prod",
            ),
            ("kubectl delete deploy api -n prod", "namespace=prod"),
            (
                "kubectl --namespace=production delete deploy api",
                "namespace=production",
            ),
            (
                "az account set --subscription prod-sub; az group delete -n x",
                "azure-subscription=prod-sub",
            ),
        ] {
            let ctx = detect_for_command(&env, &cfg, cmd);
            assert!(
                ctx.labels.contains(&label.to_string()),
                "{cmd}: {:?}",
                ctx.labels
            );
            assert_eq!(ctx.risk_level, RiskLevel::Critical, "{cmd}");
        }
        let ctx = detect_for_command(&env, &cfg, "aws --profile dev s3 rb s3://b --force");
        assert_eq!(ctx.risk_level, RiskLevel::Normal);
        // Domain signals are only kept for matching check groups.
        let ctx = detect_for_command(&env, &cfg, "AWS_PROFILE=prod rm -rf build");
        let groups: std::collections::HashSet<&str> = ["fs"].into_iter().collect();
        assert_eq!(
            ctx.filter_for_groups(&groups, &cfg).risk_level,
            RiskLevel::Normal
        );
    }

    #[test]
    fn test_remote_payload_does_not_use_local_k8s_context() {
        let env = env_with_k8s("prod-eu");
        let ctx = detect_for_command(
            &env,
            &default_config(),
            "ssh bastion kubectl delete ns payments",
        );
        assert!(ctx.k8s_context.is_none(), "{ctx:?}");
        let ctx = detect_for_command(
            &env,
            &default_config(),
            "docker exec web kubectl delete ns x",
        );
        assert!(ctx.k8s_context.is_none(), "{ctx:?}");
        // A production host name is itself a signal.
        let ctx = detect_for_command(
            &env,
            &default_config(),
            "ssh deploy@prod-db 'rm -rf /var/lib/x'",
        );
        assert_eq!(ctx.risk_level, RiskLevel::Critical);
        assert!(
            ctx.labels.contains(&"remote=prod-db".to_string()),
            "{ctx:?}"
        );
    }

    #[test]
    fn test_sensitive_paths() {
        let mut cfg = default_config();
        cfg.sensitive_paths = vec!["~/.ssh".into(), "/srv".into()];
        let env = MockEnvironment {
            cwd: "/home/dev/.ssh".into(),
            home: Some("/home/dev".into()),
            ..Default::default()
        };
        for cmd in [
            "rm -rf ~/.ssh",
            "rm id_ed25519",
            "rm -rf /home/dev/.ssh/keys",
            "echo x > ~/.ssh/authorized_keys",
            "mv /srv/app /tmp/",
            "cp evil /srv/app/config",
            "rm -rf ~",
            "cd /srv && rm -rf app",
        ] {
            let ctx = detect_for_command(&env, &cfg, cmd);
            assert!(!ctx.sensitive_paths.is_empty(), "{cmd}");
            assert_eq!(ctx.risk_level, RiskLevel::Critical, "{cmd}");
        }
        let env = MockEnvironment {
            cwd: "/home/dev/projects".into(),
            home: Some("/home/dev".into()),
            ..Default::default()
        };
        for cmd in [
            "rm -rf build",
            "cp ~/.ssh/id_ed25519.pub /tmp/",
            "ls ~/.ssh",
            "ssh host rm -rf /srv/app",
        ] {
            let ctx = detect_for_command(&env, &cfg, cmd);
            assert!(ctx.sensitive_paths.is_empty(), "{cmd}: {ctx:?}");
        }
    }

    #[test]
    fn test_invisible_characters_in_branch() {
        let env = env_with_branch("main\u{200b}");
        let ctx = detect_for_command(&env, &default_config(), "git push -f");
        assert_eq!(ctx.risk_level, RiskLevel::Critical);
        assert!(
            ctx.labels.contains(&"branch=main\\u{200b}".to_string()),
            "{:?}",
            ctx.labels
        );
        assert_eq!(escape_invisible("a\u{202e}b"), "a\\u{202e}b");
        assert_eq!(escape_invisible("plain"), "plain");
        // Free text keeps joiners and variation selectors, not bidi controls.
        assert_eq!(
            escape_invisible_text("m\u{200c}k \u{1F469}\u{200d}\u{1F4BB} \u{2764}\u{fe0f}"),
            "m\u{200c}k \u{1F469}\u{200d}\u{1F4BB} \u{2764}\u{fe0f}"
        );
        assert_eq!(
            escape_invisible_text("a\u{202e}b\u{200b}"),
            "a\\u{202e}b\\u{200b}"
        );
        assert_eq!(escape_invisible_text("a\u{1b}[2Jb"), "a\\u{1b}[2Jb");
        assert!(branch_matches_any("ma\u{2060}in", &["main".to_string()]));
    }

    #[test]
    fn test_targets_in_compound_and_nested_commands() {
        let t = targets("cd repo && git push -f origin main; echo done");
        assert_eq!(t.git_targets, vec!["main"]);
        let t = targets("bash -c 'git push -f origin main'");
        assert_eq!(t.git_targets, vec!["main"]);
        let t = targets("sudo -E env FOO=1 kubectl --context=prod delete ns a");
        assert_eq!(t.k8s_context.as_deref(), Some("prod"));
        assert!(t.sudo_root);
        assert!(t.mentions_k8s);
        let t = targets("echo 'kubectl --context prod' # comment");
        assert!(!t.mentions_k8s);
    }

    // -----------------------------------------------------------------------
    // Reasons
    // -----------------------------------------------------------------------

    #[test]
    fn test_risk_reasons() {
        let ctx = RuntimeContext {
            is_ssh: true,
            git_branch: Some("main".into()),
            ..Default::default()
        };
        let reasons: Vec<String> = ctx
            .risk_reasons(&default_config())
            .into_iter()
            .map(|(_, r)| r)
            .collect();
        assert_eq!(reasons, vec!["protected branch `main`", "SSH session"]);
    }

    #[test]
    fn test_effective_challenge_note() {
        let e = EffectiveChallenge {
            base: Challenge::Math,
            challenge: Challenge::Yes,
            reasons: vec!["protected branch `main`".into(), "SSH session".into()],
        };
        assert_eq!(
            e.note().unwrap(),
            "Escalated to Yes (from Math): protected branch `main`, SSH session"
        );
        let same = EffectiveChallenge {
            base: Challenge::Math,
            challenge: Challenge::Math,
            reasons: vec![],
        };
        assert!(same.note().is_none());
    }

    // -----------------------------------------------------------------------
    // filter_for_groups tests
    // -----------------------------------------------------------------------

    fn full_context() -> RuntimeContext {
        let mut ctx = RuntimeContext {
            is_ssh: true,
            git_branch: Some("main".into()),
            k8s_context: Some("prod-us-east-1".into()),
            env_signals: vec!["NODE_ENV=production".into()],
            ..Default::default()
        };
        ctx.refresh(&default_config());
        ctx
    }

    #[test]
    fn test_filter_git_command_hides_k8s() {
        let ctx = full_context();
        let groups: std::collections::HashSet<&str> = ["git"].into_iter().collect();
        let filtered = ctx.filter_for_groups(&groups, &default_config());

        assert_eq!(filtered.git_branch, Some("main".into()));
        assert!(filtered.k8s_context.is_none());
        assert!(filtered.labels.contains(&"branch=main".to_string()));
        assert!(!filtered.labels.iter().any(|l| l.starts_with("k8s=")));
    }

    #[test]
    fn test_filter_k8s_command_hides_branch() {
        let ctx = full_context();
        let groups: std::collections::HashSet<&str> = ["kubernetes"].into_iter().collect();
        let filtered = ctx.filter_for_groups(&groups, &default_config());

        assert!(filtered.git_branch.is_none());
        assert_eq!(filtered.k8s_context, Some("prod-us-east-1".into()));
        assert!(!filtered.labels.iter().any(|l| l.starts_with("branch=")));
        assert!(filtered.labels.contains(&"k8s=prod-us-east-1".to_string()));
    }

    #[test]
    fn test_filter_fs_command_global_only() {
        let ctx = full_context();
        let groups: std::collections::HashSet<&str> = ["fs"].into_iter().collect();
        let filtered = ctx.filter_for_groups(&groups, &default_config());

        assert!(filtered.git_branch.is_none());
        assert!(filtered.k8s_context.is_none());
        assert!(filtered.is_ssh);
        assert!(filtered.labels.contains(&"ssh=true".to_string()));
        assert!(!filtered.labels.iter().any(|l| l.starts_with("branch=")));
        assert!(!filtered.labels.iter().any(|l| l.starts_with("k8s=")));
    }

    #[test]
    fn test_filter_compound_git_and_k8s() {
        let ctx = full_context();
        let groups: std::collections::HashSet<&str> = ["git", "kubernetes"].into_iter().collect();
        let filtered = ctx.filter_for_groups(&groups, &default_config());

        assert_eq!(filtered.git_branch, Some("main".into()));
        assert_eq!(filtered.k8s_context, Some("prod-us-east-1".into()));
        assert!(filtered.labels.contains(&"branch=main".to_string()));
        assert!(filtered.labels.contains(&"k8s=prod-us-east-1".to_string()));
    }

    #[test]
    fn test_filter_global_signals_never_hidden() {
        let mut ctx = RuntimeContext {
            is_ssh: true,
            is_root: true,
            git_branch: Some("main".into()),
            k8s_context: Some("prod".into()),
            env_signals: vec!["NODE_ENV=production".into()],
            ..Default::default()
        };
        ctx.refresh(&default_config());
        // Even with an unrelated group, SSH, root, and env_signals remain
        let groups: std::collections::HashSet<&str> = ["fs"].into_iter().collect();
        let filtered = ctx.filter_for_groups(&groups, &default_config());

        assert!(filtered.is_ssh);
        assert!(filtered.is_root);
        assert_eq!(filtered.env_signals, vec!["NODE_ENV=production"]);
        assert!(filtered.labels.contains(&"ssh=true".to_string()));
        assert!(filtered.labels.contains(&"root=true".to_string()));
    }

    #[test]
    fn test_filter_risk_level_recomputed() {
        // Context with only branch=main making it Critical
        let mut ctx = RuntimeContext {
            git_branch: Some("main".into()),
            ..Default::default()
        };
        ctx.refresh(&default_config());
        assert_eq!(ctx.risk_level, RiskLevel::Critical);
        // Matched groups: {"fs"} — branch is irrelevant, so risk drops
        let groups: std::collections::HashSet<&str> = ["fs"].into_iter().collect();
        let filtered = ctx.filter_for_groups(&groups, &default_config());

        assert!(filtered.git_branch.is_none());
        assert_eq!(filtered.risk_level, RiskLevel::Normal);
    }

    // -----------------------------------------------------------------------
    // Position-aware context (switches apply only to later commands)
    // -----------------------------------------------------------------------

    /// The relevant context of `cmd`, attributing checks to commands by a
    /// crude program → group mapping (the real matcher lives in checks.rs).
    fn relevant(env: &MockEnvironment, cmd: &str) -> RuntimeContext {
        relevant_in(env, cmd)
    }

    fn relevant_in(env: &dyn Environment, cmd: &str) -> RuntimeContext {
        let cfg = default_config();
        let groups_of = |text: &str| -> std::collections::HashSet<String> {
            let mut g = std::collections::HashSet::new();
            let p = crate::parser::parse(text);
            for s in &p.segments {
                let first = s.split(' ').next().unwrap_or("");
                let group = match first {
                    "kubectl" | "helm" => "kubernetes",
                    "git" => "git",
                    "terraform" | "pulumi" => "terraform",
                    "aws" => "aws",
                    "rm" => "fs",
                    _ => continue,
                };
                if s.contains("delete")
                    || s.contains("destroy")
                    || s.contains("cordon")
                    || s.contains(" -f")
                    || s.contains("--hard")
                    || s.contains("rb ")
                    || first == "rm"
                {
                    g.insert(group.to_string());
                }
            }
            g
        };
        let all: std::collections::HashSet<&str> = ["kubernetes", "git", "terraform", "fs", "aws"]
            .into_iter()
            .collect();
        command_contexts(env, &cfg, cmd).relevant(&cfg, &groups_of, &all)
    }

    fn env_branch_k8s(branch: &str, k8s: &str) -> MockEnvironment {
        let mut env = env_with_branch(branch);
        env.command_outputs
            .insert("kubectl config current-context".into(), k8s.into());
        env
    }

    #[test]
    fn test_switch_after_the_risky_command_does_not_apply() {
        let env = env_branch_k8s("main", "prod-eu");
        for cmd in [
            "kubectl delete deploy api; kubectx dev",
            "kubectl delete deploy api && kubectl config use-context dev",
            "kubectl delete deploy api && kubectl config use dev",
            "kubectx prod-eu && kubectl delete deploy api && kubectx dev",
            "git push -f; git checkout feature/login",
            "git reset --hard HEAD~1 && git checkout feature/login",
            "TF_WORKSPACE=prod terraform destroy; terraform workspace select dev",
            "terraform workspace select prod && terraform destroy && terraform workspace select dev",
            "export NODE_ENV=production; kubectl cordon n1; unset NODE_ENV",
        ] {
            let ctx = relevant(&env, cmd);
            assert_eq!(ctx.risk_level, RiskLevel::Critical, "{cmd}: {ctx:?}");
            assert!(
                !ctx.labels.iter().any(|l| l == "k8s=dev"),
                "{cmd}: {:?}",
                ctx.labels
            );
        }
        // The other direction: the delete runs in dev.
        let env = env_branch_k8s("feature/login", "dev");
        for cmd in [
            "kubectl delete deploy api && kubectx prod-eu",
            "git push -f; git checkout main",
            "terraform destroy; terraform workspace select prod",
            "kubectl cordon n1; export NODE_ENV=production",
        ] {
            let ctx = relevant(&env, cmd);
            assert_eq!(ctx.risk_level, RiskLevel::Normal, "{cmd}: {ctx:?}");
        }
        let ctx = relevant(&env, "kubectl delete deploy api && kubectx prod-eu");
        assert!(ctx.labels.contains(&"k8s=dev".to_string()), "{ctx:?}");
        // Forward switches still apply.
        for cmd in [
            "kubectx prod-eu && kubectl delete deploy api",
            "kubie ctx prod-eu && kubectl delete deploy api",
            "kubectl config use prod-eu && kubectl delete deploy api",
            "if kubectx prod-eu; then kubectl delete deploy api; fi",
            "git checkout main && git push -f",
            "terraform workspace select prod; terraform destroy",
        ] {
            let ctx = relevant(&env, cmd);
            assert_eq!(ctx.risk_level, RiskLevel::Critical, "{cmd}: {ctx:?}");
        }
        // `unset` removes a production variable of the process environment.
        let mut env = MockEnvironment::default();
        env.env_vars.insert("NODE_ENV".into(), "production".into());
        let ctx = relevant(&env, "unset NODE_ENV; kubectl cordon n1");
        assert_eq!(ctx.risk_level, RiskLevel::Normal, "{ctx:?}");
    }

    #[test]
    fn test_kubectl_exec_payload_keeps_cluster_context() {
        let env = env_branch_k8s("main", "prod-eu");
        for cmd in [
            "kubectl exec -it api-1 -- rm -rf /data",
            "kubectl -n prod exec api-1 -- sh -c 'rm -rf /data'",
        ] {
            let ctx = relevant(&env, cmd);
            assert_eq!(ctx.risk_level, RiskLevel::Critical, "{cmd}: {ctx:?}");
            assert!(
                !ctx.labels.iter().any(|l| l.starts_with("branch=")),
                "{ctx:?}"
            );
        }
        let env = env_branch_k8s("main", "dev");
        for cmd in [
            "kubectl --context prod-eu exec api-1 -- rm -rf /data",
            "kubectl exec --context=prod-eu api-1 -- rm -rf /data",
        ] {
            let ctx = relevant(&env, cmd);
            assert!(
                ctx.labels.contains(&"k8s=prod-eu".to_string()),
                "{cmd}: {ctx:?}"
            );
            assert_eq!(ctx.risk_level, RiskLevel::Critical, "{cmd}");
        }
    }

    #[test]
    fn test_wrappers_keep_context_and_root() {
        let env = env_with_k8s("prod-eu");
        for cmd in [
            "su -c 'kubectl cordon n1'",
            "runuser -l root -c 'kubectl cordon n1'",
            "flock /tmp/l -c 'kubectl cordon n1'",
            "script -c 'kubectl cordon n1' /dev/null",
            "env -S 'kubectl cordon n1'",
            "sudo su -c 'kubectl delete deploy api'",
            "chrt -f 10 kubectl cordon n1",
            "taskset -c 0 kubectl cordon n1",
            "nsenter -t 1 -m -- kubectl cordon n1",
            "nocorrect kubectl cordon n1",
        ] {
            let ctx = relevant(&env, cmd);
            assert!(
                ctx.labels.contains(&"k8s=prod-eu".to_string()),
                "{cmd}: {ctx:?}"
            );
        }
        let env = MockEnvironment::default();
        for cmd in [
            "su -c 'rm -rf ./build'",
            "su - root -c 'rm -rf ./build'",
            "pkexec rm -rf ./build",
            "runuser -u root -- rm -rf ./build",
            "sudo su -c 'rm -rf ./build'",
        ] {
            let ctx = relevant(&env, cmd);
            assert!(ctx.is_root, "{cmd}: {ctx:?}");
        }
        for cmd in [
            "su - postgres -c 'rm -rf ./build'",
            "runuser -u nobody -- rm -rf ./build",
            "pkexec --user bob rm -rf ./build",
        ] {
            assert!(!relevant(&env, cmd).is_root, "{cmd}");
        }
    }

    #[test]
    fn test_ssh_payload_explicit_signals() {
        let env = env_branch_k8s("main", "dev");
        for cmd in [
            "ssh bastion kubectl --context prod-eu delete deploy api",
            "ssh bastion 'kubectl --context prod-eu delete deploy api'",
            "ssh bastion TF_WORKSPACE=prod terraform destroy",
            "ssh bastion 'git push -f origin main'",
            "ssh bastion sudo rm -rf /etc",
        ] {
            let ctx = relevant(&env, cmd);
            assert_eq!(ctx.risk_level, RiskLevel::Critical, "{cmd}: {ctx:?}");
        }
        // Local state is not attached to a remote payload.
        let ctx = relevant(&env, "ssh bastion 'git push -f'");
        assert!(ctx.git_branch.is_none(), "{ctx:?}");
        let env = env_with_k8s("prod-eu");
        let ctx = relevant(&env, "ssh bastion kubectl delete ns payments");
        assert!(ctx.k8s_context.is_none(), "{ctx:?}");
    }

    #[test]
    fn test_more_cloud_signals() {
        let env = MockEnvironment::default();
        for cmd in [
            "AWS_PROFILE=prod terraform destroy",
            "export AWS_PROFILE=prod; terraform destroy",
            "AWS_DEFAULT_PROFILE=prod aws s3 rb s3://b --force",
            "gcloud projects delete acme-prod",
            "az account set -s prod-sub && az group delete -n x",
        ] {
            let ctx = command_contexts(&env, &default_config(), cmd).full(&default_config());
            assert_eq!(ctx.risk_level, RiskLevel::Critical, "{cmd}: {ctx:?}");
        }
        let ctx = relevant(&env, "AWS_PROFILE=prod terraform destroy");
        assert!(
            ctx.labels.contains(&"aws-profile=prod".to_string()),
            "{ctx:?}"
        );
        // `kubectl delete ns prod`: the namespace being deleted.
        let env = env_with_k8s("dev");
        let ctx = relevant(&env, "kubectl delete ns prod");
        assert!(
            ctx.labels.contains(&"namespace=prod".to_string()),
            "{ctx:?}"
        );
    }

    #[test]
    fn test_k8s_unknown_and_not_checked_and_ssh_client() {
        // KUBECONFIG pointing at a missing file.
        let env = env_with_k8s("dev");
        let ctx = relevant(&env, "KUBECONFIG=/nonexistent kubectl delete deploy api");
        assert!(ctx.labels.contains(&"k8s=unknown".to_string()), "{ctx:?}");
        let mut env = env_with_k8s("dev");
        env.env_vars
            .insert("KUBECONFIG".into(), "/nonexistent".into());
        let ctx = relevant(&env, "kubectl delete deploy api");
        assert!(ctx.labels.contains(&"k8s=unknown".to_string()), "{ctx:?}");
        // `--no-context` and no kubeconfig file.
        let base = MockEnvironment::default();
        let env = crate::env::NoContextEnvironment::new(&base);
        let ctx = relevant_in(&env, "kubectl delete deploy api");
        assert!(
            ctx.labels.contains(&"k8s=not checked".to_string()),
            "{ctx:?}"
        );
        // SSH_CLIENT alone.
        let mut env = MockEnvironment::default();
        env.env_vars
            .insert("SSH_CLIENT".into(), "1.2.3.4 5 22".into());
        assert!(detect(&env, &default_config()).is_ssh);
    }

    #[test]
    fn test_clustered_dash_c_and_target_dirs() {
        let env = MockEnvironment::default();
        let ctx = relevant(&env, "su -lc 'rm -rf ./build'");
        assert!(ctx.is_root, "{ctx:?}");
        let ctx = relevant(&env, "script -qc 'rm -rf ./build' /dev/null");
        assert!(!ctx.is_root, "{ctx:?}");
        let dirs = command_target_dirs(
            "cd ../infra && cd envs; git -C ../app push; terraform -chdir=prod plan; make -C sub; GIT_DIR=/r/.git git log",
        );
        let dirs: Vec<String> = dirs.iter().map(|d| d.display().to_string()).collect();
        assert_eq!(
            dirs,
            vec![
                "../infra",
                "../infra/envs",
                "../infra/app",
                "../infra/envs/prod",
                "../infra/envs/sub",
                "/r/.git"
            ]
        );
        assert!(is_tightening_mode("600"));
        assert!(is_tightening_mode("0400"));
        assert!(is_tightening_mode("go-rwx"));
        assert!(!is_tightening_mode("644"));
        assert!(!is_tightening_mode("4700"));
        assert!(!is_tightening_mode("u+x"));
    }

    fn env_with_kubeconfig(branch: &str, current: &str) -> MockEnvironment {
        let mut env = env_branch_k8s(branch, current);
        env.home = Some(PathBuf::from("/home/u"));
        env.files.insert(
            PathBuf::from("/home/u/.kube/config"),
            format!(
                "apiVersion: v1\nkind: Config\ncurrent-context: {current}\ncontexts:\n- name: prod-eu\n  context:\n    cluster: c1\n- context:\n    cluster: c2\n  name: dev\nclusters: []\n"
            ),
        );
        env
    }

    #[test]
    fn test_a_switch_that_may_fail_keeps_the_old_context() {
        let env = env_with_kubeconfig("main", "prod-eu");
        // The switch may fail (typo, `;`, `||`, `&`): prod still applies.
        for cmd in [
            "kubectx nope; kubectl delete deploy api",
            "kubectl config use-context does-not-exist; kubectl delete deploy api",
            "kubectx dev || kubectl delete deploy api",
            "kubectx dev; kubectl delete deploy api",
            "kubectx dev & kubectl delete deploy api",
            "kubectx nope && kubectl delete deploy api",
            "kubectx dev && kubectl get pods; kubectl delete deploy api",
            "kubectx nope; kubectx dev; kubectl delete deploy api",
        ] {
            let ctx = relevant(&env, cmd);
            assert_eq!(ctx.risk_level, RiskLevel::Critical, "{cmd}: {ctx:?}");
            // The banner says why the old context was kept.
            assert!(
                ctx.labels
                    .iter()
                    .any(|l| l == "k8s=prod-eu"
                        || l.starts_with("k8s=prod-eu (kept: the switch to ")),
                "{cmd}: {:?}",
                ctx.labels
            );
        }
        // A switch to a known context that must succeed first applies.
        for cmd in [
            "kubectx dev && kubectl delete deploy api",
            "kubectl config use-context dev && kubectl delete deploy api",
            "kubectx nope; kubectx dev && kubectl delete deploy api",
        ] {
            let ctx = relevant(&env, cmd);
            assert_eq!(ctx.risk_level, RiskLevel::Normal, "{cmd}: {ctx:?}");
        }
        // git: a checkout that may fail keeps the protected branch.
        let env = env_with_kubeconfig("main", "dev");
        for cmd in [
            "git checkout no-such-branch; git push -f",
            "git checkout feature/login || git push -f",
            "git switch nope; git reset --hard HEAD~1",
            "git checkout nope && git push -f",
        ] {
            let ctx = relevant(&env, cmd);
            assert_eq!(ctx.risk_level, RiskLevel::Critical, "{cmd}: {ctx:?}");
            assert!(
                ctx.labels.iter().any(|l| l.starts_with("branch=main")),
                "{cmd}: {:?}",
                ctx.labels
            );
        }
        let ctx = relevant(&env, "git checkout -b fix && git push -f");
        assert_eq!(ctx.risk_level, RiskLevel::Normal, "{ctx:?}");
    }

    #[test]
    fn test_variable_contexts_and_terraform_dirs() {
        let env = env_with_kubeconfig("feature/login", "dev");
        for cmd in [
            "for c in prod-eu dev; do kubectl --context $c delete deploy api; done",
            "C=prod-eu; kubectl --context $C delete deploy api",
            "kubectl --context \"$(echo prod-eu)\" delete deploy api",
            "terraform -chdir=envs/prod destroy",
            "terraform destroy -var-file=prod.tfvars",
            "cd envs/prod && terraform destroy",
        ] {
            let ctx = relevant(&env, cmd);
            assert_eq!(ctx.risk_level, RiskLevel::Critical, "{cmd}: {ctx:?}");
        }
        let ctx = relevant(&env, "kubectl --context $UNSET delete deploy api");
        assert!(ctx.labels.contains(&"k8s=unknown".to_string()), "{ctx:?}");
        assert_eq!(ctx.risk_level, RiskLevel::Elevated, "{ctx:?}");
        let ctx = relevant(&env, "terraform -chdir=envs/dev destroy");
        assert_eq!(ctx.risk_level, RiskLevel::Normal, "{ctx:?}");
    }

    #[test]
    fn test_force_with_lease_to_a_protected_branch() {
        let cfg = default_config();
        let env = env_with_branch("main");
        let lease = |env: &MockEnvironment, cmd: &str| {
            protected_force_with_lease(env, &cfg, cmd, &crate::parser::parse(cmd))
        };
        assert_eq!(
            lease(&env, "git push --force-with-lease").as_deref(),
            Some("main")
        );
        assert_eq!(
            lease(&env, "git push --force-with-lease origin main").as_deref(),
            Some("main")
        );
        assert_eq!(
            lease(&env, "git push --force-with-lease origin feature/x"),
            None
        );
        assert_eq!(lease(&env, "git push origin main"), None);
        let env = env_with_branch("feature/login");
        assert_eq!(lease(&env, "git push --force-with-lease"), None);
        assert_eq!(
            lease(
                &env,
                "git push --force-if-includes --force-with-lease origin HEAD:main"
            )
            .as_deref(),
            Some("main")
        );
    }

    #[test]
    fn test_force_with_lease_to_a_computed_target() {
        let cfg = default_config();
        let env = env_with_branch("main");
        let lease =
            |cmd: &str| protected_force_with_lease(&env, &cfg, cmd, &crate::parser::parse(cmd));
        for cmd in [
            "git push --force-with-lease origin $(git branch --show-current)",
            "git push --force-with-lease origin $(git_current_branch)",
            "for b in main dev; do git push --force-with-lease origin $b; done",
            "echo main | xargs -I{} git push --force-with-lease origin {}",
        ] {
            assert_eq!(lease(cmd).as_deref(), Some("main"), "{cmd}");
        }
        // Only known when the line runs: reported as unknown, never as a
        // branch name it may not be.
        for cmd in [
            "git push --force-with-lease origin $B",
            "git push --force-if-includes origin $B",
            "git push --force-with-lease origin +$B",
            "git push --force-with-lease origin $(cat /tmp/branchname)",
        ] {
            assert_eq!(lease(cmd).as_deref(), Some(UNKNOWN_PUSH_TARGET), "{cmd}");
        }
        assert_eq!(lease("git push --force-with-lease origin feature/x"), None);
    }

    #[test]
    fn test_oh_my_zsh_current_branch_helpers_on_a_feature_branch() {
        // `ggfl`, `ggpush`, `gpsup` (oh-my-zsh) print the checked-out
        // branch: on a feature branch they are not a protected push.
        let cfg = default_config();
        let env = env_with_branch("feature/login");
        let lease =
            |cmd: &str| protected_force_with_lease(&env, &cfg, cmd, &crate::parser::parse(cmd));
        for cmd in [
            "git push --force-with-lease origin $(git_current_branch)",
            "git push --force-with-lease origin \"$(git_current_branch)\"",
            "git push --set-upstream --force-with-lease origin $(current_branch)",
            "git push --force-with-lease origin $(command git_current_branch)",
            "[[ \"$#\" != 1 ]] && local b=\"$(git_current_branch)\"; git push --force-with-lease origin \"${b:=$1}\"",
            "git push --force-with-lease origin `git_current_branch`",
        ] {
            assert_eq!(lease(cmd), None, "{cmd}");
            let t = parse_command_targets(cmd);
            assert!(
                t.segments.iter().any(|s| s.git_uses_current)
                    && !t.segments.iter().any(|s| s.git_target_unknown),
                "{cmd}: {t:?}"
            );
        }
        // `${B:=main}` with `B` unset is `main`.
        assert_eq!(
            lease("git push --force-with-lease origin \"${B:=main}\"").as_deref(),
            Some("main")
        );
    }

    #[test]
    fn test_hosting_platform_runs_are_remote_and_production_escalates() {
        let cfg = default_config();
        let env = MockEnvironment {
            cwd: "/app".into(),
            ..Default::default()
        };
        let ctx = detect_for_command(
            &env,
            &cfg,
            "heroku pg:psql --command 'DELETE FROM users' -a shop-prod",
        );
        assert!(
            ctx.labels.iter().any(|l| l == "remote=heroku:shop-prod"),
            "{:?}",
            ctx.labels
        );
        assert_eq!(ctx.risk_level, RiskLevel::Critical);
        let ctx = detect_for_command(&env, &cfg, "fly ssh console -a web-dev -C 'ls'");
        assert!(
            ctx.labels.iter().any(|l| l == "remote=fly:web-dev"),
            "{:?}",
            ctx.labels
        );
        assert_ne!(ctx.risk_level, RiskLevel::Critical);
    }

    #[test]
    fn test_unknown_push_target_is_labelled_unknown_not_main() {
        // On a feature branch of a repository that has `main`, an
        // unknown target escalates (it may be `main`) but is labelled
        // `target=unknown`, never `target=main`.
        let cfg = default_config();
        let mut env = env_with_branch("feature/login");
        env.files.insert(
            "/repo/.git/HEAD".into(),
            "ref: refs/heads/feature/login\n".into(),
        );
        env.files
            .insert("/repo/.git/refs/heads/main".into(), "0123abcd\n".into());
        let mut escalated = 0;
        for cmd in [
            "git push --force-with-lease origin $B",
            "git push --force-with-lease origin $(cat /tmp/branchname)",
            "git push -f origin \"$@\"",
        ] {
            let ctx = detect_for_command(&env, &cfg, cmd);
            assert!(
                !ctx.git_targets.iter().any(|t| t == "main"),
                "{cmd}: {ctx:?}"
            );
            if ctx.git_target_unknown {
                escalated += 1;
                assert_eq!(ctx.risk_level, RiskLevel::Critical, "{cmd}");
                assert!(ctx.labels.iter().any(|l| l == "target=unknown"), "{cmd}");
                assert!(
                    !ctx.labels.iter().any(|l| l.contains("target=main")),
                    "{cmd}"
                );
                let reasons: Vec<String> =
                    ctx.risk_reasons(&cfg).into_iter().map(|(_, r)| r).collect();
                assert!(
                    reasons.iter().all(|r| !r.contains("`main`")),
                    "{cmd}: {reasons:?}"
                );
            }
        }
        assert!(escalated >= 2, "unknown targets still escalate");
        // Without a protected branch in the repository: no escalation.
        let env = env_with_branch("feature/login");
        let ctx = detect_for_command(&env, &cfg, "git push --force-with-lease origin $B");
        assert!(!ctx.git_target_unknown, "{ctx:?}");
    }

    #[test]
    fn test_redirections_are_not_arguments() {
        let t = parse_command_targets("git push -f >/dev/null 2>&1");
        assert!(t.git_uses_current, "{t:?}");
        assert!(t.git_targets.is_empty(), "{t:?}");
        let t = parse_command_targets("git push -f origin main > /dev/null");
        assert_eq!(t.git_targets, vec!["main".to_string()]);
        let t = parse_command_targets("git reset --hard 2>&1");
        assert!(!t.git_uses_current, "{t:?}");
        let t = parse_command_targets("git reset --hard </dev/null &>log");
        assert!(!t.git_uses_current, "{t:?}");
        assert_eq!(
            tokenize_segments("diff b 2>/dev/null")[0],
            vec!["diff".to_string(), "b".to_string()]
        );
    }

    #[test]
    fn test_discard_with_other_risky_command_is_not_protected_branch() {
        let env = env_with_branch("main");
        for cmd in [
            "rm -rf build && git reset --hard",
            "git reset --hard && rm -rf build",
            "rm -rf node_modules && git checkout -- .",
        ] {
            let ctx = relevant(&env, cmd);
            assert_eq!(ctx.risk_level, RiskLevel::Normal, "{cmd}: {ctx:?}");
        }
        let ctx = relevant(&env, "rm -rf build && git reset --hard HEAD~1");
        assert_eq!(ctx.risk_level, RiskLevel::Critical);
    }

    #[test]
    fn test_child_shell_sees_prefix_assignment() {
        let t = parse_command_targets("B=feature; B=main bash -c 'git push -f origin $B'");
        assert!(t.git_targets.contains(&"main".to_string()), "{t:?}");
        let t = parse_command_targets("B=main; B=feature bash -c 'git push -f origin $B'");
        assert_eq!(t.git_targets, vec!["feature".to_string()]);
    }

    #[test]
    fn test_velero_argocd_and_tf_chdir_contexts() {
        let t = parse_command_targets("velero backup delete nightly --kubecontext prod-eu");
        assert_eq!(t.segments[0].k8s_context.as_deref(), Some("prod-eu"));
        assert!(t.mentions_k8s);
        let t = parse_command_targets("argocd app delete api --kube-context prod-eu");
        assert_eq!(t.segments[0].k8s_context.as_deref(), Some("prod-eu"));
        let t = parse_command_targets("argocd app delete api --server argocd.prod.example.com");
        assert_eq!(
            t.segments[0].cluster.as_deref(),
            Some("argocd.prod.example.com")
        );
        let t = parse_command_targets("terraform -chdir=$ENV destroy");
        assert!(t.segments[0].tf_dir_unknown);
        let t = parse_command_targets("ENV=envs/dev; terraform -chdir=$ENV destroy");
        assert!(!t.segments.iter().any(|s| s.tf_dir_unknown));
    }

    #[test]
    fn test_literal_context_loop_is_not_a_failed_switch() {
        let env = env_with_k8s("dev");
        let ctx = relevant(
            &env,
            "for c in dev prod-eu; do kubectl --context $c delete deploy api; done",
        );
        assert_eq!(ctx.k8s_context.as_deref(), Some("prod-eu"));
        assert!(
            !ctx.labels.iter().any(|l| l.contains("may fail")),
            "{:?}",
            ctx.labels
        );
    }

    #[test]
    fn test_target_dirs_are_bounded_and_normalized() {
        let cmd = "cd a && ".repeat(5000) + "rm -rf /";
        let dirs = command_target_dirs(&cmd);
        assert!(dirs.len() <= MAX_TARGET_DIRS, "{}", dirs.len());
        assert!(dirs
            .iter()
            .all(|d| d.as_os_str().len() <= MAX_TARGET_DIR_LEN));
        assert_eq!(
            command_target_dirs("cd a && cd .. && cd b"),
            vec![PathBuf::from("a"), PathBuf::from("."), PathBuf::from("b")]
        );
        assert!(command_target_dirs("env -C /srv/app make").contains(&PathBuf::from("/srv/app")));
        assert!(command_target_dirs("/srv/app/scripts/deploy prod")
            .contains(&PathBuf::from("/srv/app/scripts")));
    }
}
