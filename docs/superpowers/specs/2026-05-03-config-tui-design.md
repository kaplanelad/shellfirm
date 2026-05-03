# Design — Convert `shellfirm config` from a Sequential CLI to a Full-Screen TUI

**Date:** 2026-05-03
**Author:** Elad Kaplan (with Claude as collaborator)
**Status:** Design — pending implementation plan

---

## 1. Problem

Today, `shellfirm config` runs a series of `requestty` prompts (radio selects, multi-selects, free-text inputs) executed one after another. Each subcommand (`config challenge`, `config severity`, `config groups`, …) drives a separate prompt flow, and the only way to see the resulting YAML is to run `shellfirm config show` after the fact. There's no live preview, no validation gate before write, and no single place to see the full state of a configuration.

The user goal: **replace the sequential CLI with a full-screen Terminal UI (TUI) that lets users edit every setting from one screen, validates the full config before saving, and shows them exactly what's about to be written.**

## 2. Goals

1. The UI ships **inside the existing binary** — no separate process, no extra install step.
2. Every field that can be a **closed list** (enums, known IDs, bools) is exposed as a picker, radio, multi-select, or toggle. Free-form text only when the underlying domain is genuinely free.
3. **Validate before save.** A save attempt round-trips the in-memory state through `Settings` deserialization; on failure the user sees the field-level error and the existing file is untouched.
4. **Live preview** of the YAML that would be written, behind a toggle (closed by default).
5. The TUI **adapts to terminal size** with a sensible minimum (~80×24); on narrow terminals the preview becomes a full-screen overlay instead of a split.
6. Polished UX — comparable to `lazygit` / `k9s` for navigation feel and discoverability.
7. **Comprehensive automated tests** at every layer — model, view, save validation, file I/O, integration. Tests are not optional.

## 3. Non-goals

- A web UI / browser-based dashboard. Not in scope. The binary stays self-contained terminal-only.
- A native desktop app (Tauri / egui). Out.
- Mouse support. Keyboard-only.
- Migrating the on-disk config format from YAML to JSON. The user spoke loosely about "JSON" — the format remains YAML.
- Removing the existing `shellfirm config <subcommand>` CLI flags (challenge, severity, groups, llm, …). They remain as fast paths for scripts and CI. Only `shellfirm config` with no subcommand changes — it now opens the TUI instead of the sequential menu.

## 4. High-Level Architecture

```
┌────────────────────────────────────────────────────────────┐
│  shellfirm CLI binary                                      │
│                                                            │
│   src/bin/cmd/config.rs                                    │
│      ├─ run()  ──► no subcommand?  ──► launch TUI          │
│      ├─ run()  ──► fast paths kept (challenge, …)          │
│      │                                                     │
│   src/tui/  (new module, behind `tui` cargo feature)       │
│      ├─ app.rs        ─ App state machine, event loop      │
│      ├─ model.rs      ─ DraftSettings (mutable working copy)│
│      ├─ tabs/                                              │
│      │   ├─ general.rs                                     │
│      │   ├─ groups.rs                                      │
│      │   ├─ escalation.rs                                  │
│      │   ├─ context.rs                                     │
│      │   ├─ llm.rs                                         │
│      │   ├─ ignore_deny.rs                                 │
│      │   └─ custom_checks.rs                               │
│      ├─ widgets/                                           │
│      │   ├─ radio.rs, toggle.rs, multi_select.rs, …        │
│      ├─ preview.rs    ─ YAML diff renderer                 │
│      ├─ validate.rs   ─ Settings round-trip + diagnostics  │
│      └─ check_store.rs─ Custom-check file CRUD             │
│                                                            │
│   src/checks.rs       ─ existing; add load-order fix       │
│   src/config.rs       ─ unchanged (TUI calls existing API) │
└────────────────────────────────────────────────────────────┘
```

Key idea: the TUI is a **view layer over existing config types**. It owns a `DraftSettings` (a clone of the on-disk `Settings`), mutates it in response to keystrokes, and only writes back to disk through `Config::save_settings_file_from_struct` (the existing API). The UI never touches the YAML file directly during editing.

### Library choices

- **`ratatui`** — stable, actively maintained, the de-facto Rust TUI library.
- **`crossterm`** — ratatui's default backend, cross-platform (macOS/Linux/Windows).
- **`tui-input`** — small focused crate for cursor-aware text input fields. Decision: **include it.** Rolling our own input handling for ~10 different text fields is a lot of accidental complexity for negligible binary size win. Re-evaluate later if it becomes a problem.

### Cargo feature flag

Following the existing pattern (`mcp`, `wrap`, `llm`):

```toml
[features]
default = ["all"]
tui = ["ratatui", "crossterm", "tui-input"]
all = ["cli", "llm", "mcp", "ai", "wrap", "tui"]
```

When the `tui` feature is disabled, `shellfirm config` (no subcommand) falls back to the existing sequential prompts. The fast-path subcommands work in both modes.

## 5. Field Classification

Every field in `Settings` was audited. Summary:

| Class | Count | Examples |
|---|---|---|
| **CLOSED** (radio / toggle / multi-select from a known set) | 14 | `challenge`, `min_severity`, `audit_enabled`, `enabled_groups`, `severity_escalation.*`, `agent.auto_deny_severity` |
| **HYBRID** (picker from known set + manual entry escape) | 9 | `ignores_patterns_ids`, `deny_patterns_ids`, `check_escalation` keys, `llm.provider`, `llm.model`, `wrappers.tools.*` keys, `wrappers.tools.delimiter` |
| **FREE** (no closed set possible) | 4 | `context.protected_branches`, `context.production_k8s_patterns`, `context.production_env_vars`, `context.sensitive_paths` |

Numeric fields (`llm.timeout_ms`, `llm.max_tokens`) use a stepper widget with sensible bounds (timeout 100–60000 ms; max_tokens 1–8192).

### Full classification (every field)

| Field | Class | Widget | Closed-list source |
|---|---|---|---|
| `challenge` | CLOSED | Radio (3) | enum `Challenge`: Math · Enter · Yes |
| `min_severity` | CLOSED | Radio (6) | enum `Severity` + null: all · Info · Low · Medium · High · Critical |
| `audit_enabled` | CLOSED | Toggle | bool |
| `blast_radius` | CLOSED | Toggle | bool |
| `enabled_groups[]` | CLOSED | Multi-select (21 items) | `DEFAULT_ENABLED_GROUPS` |
| `disabled_groups[]` | CLOSED | Derived (un-checked items in the same multi-select) | same |
| `ignores_patterns_ids[]` | HYBRID | Searchable picker + "Add custom" | loaded check IDs (~100) + custom IDs |
| `deny_patterns_ids[]` | HYBRID | Searchable picker + "Add custom" | same |
| `severity_escalation.enabled` | CLOSED | Toggle | bool |
| `severity_escalation.{critical,high,medium,low,info}` | CLOSED | 5×3 radio matrix | enum `Challenge` |
| `group_escalation{}` | CLOSED × CLOSED | Add row: pick group → pick challenge | 21 known groups + custom × `Challenge` |
| `check_escalation{}` | HYBRID × CLOSED | Add row: picker (or custom) → pick challenge | check IDs × `Challenge` |
| `context.protected_branches[]` | FREE | Editable list | user-defined (supports glob like `release/*`) |
| `context.production_k8s_patterns[]` | FREE | Editable list (defaults seeded) | user-defined substrings |
| `context.production_env_vars{}` | FREE × FREE | Editable key=value list | user-defined |
| `context.sensitive_paths[]` | FREE | Editable list (filesystem paths) | user-defined |
| `context.escalation.elevated` | CLOSED | Radio | enum `Challenge` |
| `context.escalation.critical` | CLOSED | Radio | enum `Challenge` |
| `agent.auto_deny_severity` | CLOSED | Radio (5) | enum `Severity` |
| `agent.require_human_approval` | CLOSED | Toggle | bool |
| `llm.provider` | HYBRID | Picker + custom | known: anthropic, openai-compatible |
| `llm.model` | HYBRID | Picker (suggestions per provider) + custom | curated suggestions per provider |
| `llm.base_url` | FREE | Text input (URL, optional) | user-defined |
| `llm.timeout_ms` | CLOSED-ish | Numeric stepper | bounded 100–60000 |
| `llm.max_tokens` | CLOSED-ish | Numeric stepper | bounded 1–8192 |
| `wrappers.tools{}.<tool>` | HYBRID | Picker (psql, redis-cli, mongo, mysql…) + custom name | curated common shells |
| `wrappers.tools{}.delimiter` | HYBRID | Picker: `;` · `\n` · Custom | known SQL/line-oriented values |
| `wrappers.tools{}.check_groups[]` | CLOSED | Multi-select | `DEFAULT_ENABLED_GROUPS` |

### HYBRID picker pattern

Every HYBRID picker behaves the same way:

```
┌─ Pick check ID ─ /git ────────────────────────────┐
│   ✓ git:force_push                  [built-in]    │  ← result of /git filter
│     git:reset_hard                  [built-in]    │
│     my_team:no_force_push_main      [custom]      │
│   ─────────────────────────────────────────────── │
│   + Add custom ID…                                │  ← escape hatch (free text)
└───────────────────────────────────────────────────┘
```

Built-in entries get a `[built-in]` badge; custom entries get a `[custom]` badge. The "+ Add custom ID…" row at the bottom prompts for a free-text value. The `/` key activates the search filter at any time.

## 6. UX Specification

### 6.1 Layout

```
┌─ shellfirm config ──────────────────────────── settings.yaml ────────┐
│  General  Groups  Escalation  Context  LLM  Ignore/Deny  Custom      │  ← tabs
├──────────────────────────────────────────────────────────────────────┤
│                                                                      │
│   [tab content — full-width form]                                    │
│                                                                      │
│                                                  unsaved changes ●   │  ← dirty marker
└──────────────────────────────────────────────────────────────────────┘
 ↑↓ move  ←→/Tab tabs  Space toggle  p preview ►  s save  r reset  q quit
```

When the user presses `p`, a preview pane slides in on the right (60/40 split). On terminals narrower than 100 cols, `p` opens a **full-screen overlay** instead of a split.

### 6.2 Tabs

| Tab | Contents |
|---|---|
| **General** | `challenge`, `min_severity`, `audit_enabled`, `blast_radius`, `agent.auto_deny_severity`, `agent.require_human_approval` |
| **Groups** | Multi-select of 21 built-in groups + every distinct `from` value across loaded custom checks (badged `custom`) |
| **Escalation** | `severity_escalation.enabled` toggle, 5×3 severity-vs-challenge matrix, group overrides editor, check-ID overrides editor |
| **Context** | Protected branches list, k8s patterns list, env-vars key/value editor, sensitive paths list, elevated/critical challenge radios |
| **LLM** | provider picker (Anthropic / openai-compatible / custom), model picker (suggestions per provider + custom), timeout stepper, max_tokens stepper, base_url text input |
| **Ignore / Deny** | Two side-by-side searchable pickers over the union of built-in + custom check IDs, with manual-entry escape for unknown IDs (e.g., a check the user plans to add) |
| **Custom** | List of all custom checks with `[+] new` `[e] edit` `[d] delete` `[f] open file in $EDITOR`. Authoring form is detailed below. |

### 6.3 Preview pane

When toggled on (key `p`), the right pane shows the YAML that **would be written**. It's diff-rendered against the on-disk file:

```
challenge: Yes
min_severity: Medium
audit_enabled: true
+ enabled_groups:    ← line(s) added vs disk
+   - aws
- enabled_groups:    ← line(s) that would be removed
-   - flyio
```

Updates on every keystroke that changes the model. Implementation: `serde_yaml::to_string(&draft)` on each change; line-diff against the original on-disk content.

### 6.4 Save flow

User presses `s`:

1. `validate()` runs: round-trip `DraftSettings` → YAML → `Settings`. Aggregates field-level errors via a `ValidationReport` struct.
2. **If invalid:** modal dialog lists each error (path + reason). The save is rejected; nothing on disk changes.
3. **If valid:** modal shows the diff against disk and a `[Save] [Cancel]` confirm. On Save, write via `Config::save_settings_file_from_struct`.

### 6.5 Help overlay (`?`)

Pressing `?` opens a full-screen modal listing every keybinding grouped by context (global, list nav, dialog, picker, custom-check editor). Press `Esc` or `?` again to close. The same hint bar at the bottom shows a condensed version always.

### 6.6 Reset / Quit / Dirty handling

- `r` (Reset) — modal confirms before reverting `DraftSettings` to on-disk state.
- `q` (Quit) — if dirty, modal asks `[Save] [Discard] [Cancel]`. If clean, exits immediately.
- The `unsaved changes ●` indicator is shown in the bottom-right of the body whenever `draft != on_disk`.

### 6.7 Keyboard map (always visible in the hint bar)

```
↑↓        navigate within a tab
←→ / Tab  switch tabs
Space     toggle a checkbox / radio at cursor
Enter     activate (open dropdown, confirm dialog)
+ / [+]   add a row (lists, custom checks, overrides)
e         edit selected row
d         delete selected row
/         filter (in pickers and lists)
p         toggle preview pane
s         save (with validate + diff)
r         reset
q         quit
?         help screen overlay
Esc       cancel/close current dialog or dropdown
```

## 7. Custom Checks (full CRUD)

### 7.1 Storage layout

**One file per group** under `~/.shellfirm/checks/`:

```
~/.shellfirm/checks/
  ├── my_team.yaml      # all checks where `from: my_team`
  ├── internal.yaml     # all checks where `from: internal`
  └── personal.yaml
```

Mirrors the built-in convention (`shellfirm/checks/git.yaml`, `fs.yaml`, …) and maps to how users mentally organize checks.

### 7.2 Authoring form fields

| Field | Widget | Validation |
|---|---|---|
| `id` | Text input | non-empty, unique across all (built-in + custom) check IDs |
| `from` (group) | Picker: 21 built-in + existing custom + "new group…" | non-empty; "new group…" prompts for a group name |
| `test` (regex) | Text input | live-compile via `regex::Regex::new`; on success show "✓ regex compiles" |
| `description` | Text input | non-empty |
| `severity` | Radio (5) | one of Info / Low / Medium / High / Critical |
| `challenge` | Radio (3) | Math / Enter / Yes |
| `alternative` | Text input (optional) | — |
| `alternative_info` | Text input (optional) | — |
| `filters` | Sub-list, add/remove via `+`/`d`. Each row picks `PathExists(N)` / `Contains(s)` / `NotContains(s)` | type-specific |

### 7.3 Operations

- **Create:** Build a `Check`, append to `~/.shellfirm/checks/<from>.yaml` (creating the file if absent). On disk we read existing file content as `Vec<Check>`, push new one, write back.
- **Edit:** Same as create, but find-and-replace the matching `id` in the source file. If `from` changed, we move the check to the new file (delete from old, append to new).
- **Delete:** Remove the matching `id` from its source file. If file ends up empty, delete the file (avoid leaving empty YAML files).
- **Reload:** Re-read the directory.

All file writes go through a `CustomCheckStore` abstraction so tests can swap a temp directory.

### 7.4 Knock-on changes elsewhere

- **Groups tab** lists 21 built-in + every distinct `from` across custom checks, badged `custom`.
- **Ignore / Deny** pickers include all custom check IDs, badged `custom`.

## 8. Pre-existing Bug Fix — Custom-Check Filtering

### 8.1 The bug

In `src/bin/shellfirm.rs`:

```rust
let mut checks = settings.get_active_checks()?;   // built-ins, filtered
let custom = load_custom_checks(&dir)?;
checks.extend(custom);                             // ← unfiltered append
```

`get_active_checks()` filters built-ins by `enabled_groups`, `disabled_groups`, and `ignores_patterns_ids`. Custom checks bypass all three filters. Effects:

- Custom checks **cannot** be disabled by un-checking their group.
- Custom checks **cannot** be ignored by adding their ID to `ignores_patterns_ids`.
- (Denial via `deny_patterns_ids` still works because it's enforced at challenge time.)

### 8.2 Fix

Move custom-check filtering into `Settings::get_active_checks` (or a sibling method), so the same enabled/disabled/ignores logic applies to both sources. Concretely:

```rust
pub fn get_active_checks_with_custom(
    &self,
    custom: &[Check],
) -> Result<Vec<Check>> {
    let enabled = self.enabled_groups.iter().map(String::as_str).collect::<HashSet<_>>();
    let disabled = self.disabled_groups.iter().map(String::as_str).collect::<HashSet<_>>();
    let ignores = self.ignores_patterns_ids.iter().map(String::as_str).collect::<HashSet<_>>();

    let filter = |c: &Check| {
        enabled.contains(c.from.as_str())
            && !disabled.contains(c.from.as_str())
            && !ignores.contains(c.id.as_str())
    };

    let mut out: Vec<Check> = all_checks_cached().iter().filter(|c| filter(c)).cloned().collect();
    out.extend(custom.iter().filter(|c| filter(c)).cloned());
    Ok(out)
}
```

`shellfirm.rs` calls `get_active_checks_with_custom(&custom)` instead of the two-step append. The old `get_active_checks` either gets removed or kept as a thin wrapper.

### 8.3 Migration concern

A user who currently has custom checks they expect to always be active — and an `enabled_groups` list that doesn't include the custom group — will see those checks become inactive after the fix. Mitigation: on first launch after upgrade, the TUI **auto-adds any custom group seen on disk to `enabled_groups`** if it isn't already present, then writes the updated config. This is a one-shot migration that preserves existing behavior. The migration is logged at `info` level.

## 9. Backwards Compatibility

- `shellfirm config <subcommand>` (challenge, severity, groups, llm, context, escalation, ignore, deny, show, reset, edit) — **all kept**, behavior unchanged.
- `shellfirm config` (no subcommand) — was: sequential menu; now: full-screen TUI. When `tui` feature is disabled, falls back to the old menu.
- On-disk YAML schema — unchanged.
- `init` command — unchanged.

## 10. Testing Strategy *(non-optional — user requirement)*

This is the section where shortcuts are most tempting and most damaging. The plan: **test every layer that has logic, isolate it from the terminal, and use snapshots for anything that renders.**

### 10.1 Unit tests — `DraftSettings` mutation API

Pure-data tests with no terminal involved.

- Each setter (`set_challenge`, `toggle_group`, `add_ignore`, `remove_ignore`, `set_severity_escalation`, …) — assert the resulting `DraftSettings` matches expectation, including idempotency (toggle twice = original).
- `is_dirty()` returns true exactly when `DraftSettings` differs from `original_on_disk`.
- `reset()` restores `original_on_disk` byte-for-byte.

### 10.2 Unit tests — validation

- `validate()` on a known-good draft → `ValidationReport::ok()`.
- `validate()` on each individual broken field (timeout = "abc", invalid challenge enum injected via `serde_yaml::Value`, duplicate check ID, malformed regex, negative max_tokens, …) → expected error messages with correct field paths.
- Round-trip: serialize a valid draft → parse back → byte-equal serialization.

### 10.3 Snapshot tests — rendered tabs

`ratatui` provides a `TestBackend` that records frames as a 2D char buffer. We use `insta` (already a dev dep) to snapshot:

- Each tab in its default state.
- Each tab with a non-default selection (e.g., Medium picked, escalation matrix populated).
- Preview-closed and preview-open variants.
- Save dialog (success and failure).
- Custom-check authoring form (empty, partially filled, with validation errors).
- Help overlay.
- Narrow-terminal layout (preview as full-screen overlay).
- Empty custom-check list and populated list.

Total snapshot count target: ~30 frames.

### 10.4 Property tests — escalation matrix

Use `proptest` (new dev-dep) on the rule "for any combination of severity inputs + draft settings, the rendered matrix and the saved YAML round-trip cleanly." Catches edge cases in the matrix widget code.

### 10.5 Integration tests — TUI driver

Drive the app with synthetic key events using `ratatui::backend::TestBackend`:

- Launch app → assert initial frame matches snapshot.
- Press `Tab` → assert second tab is highlighted.
- Press `Space` on a checkbox → assert `DraftSettings` updated and dirty marker shown.
- Press `s` → assert save dialog renders → press Enter → assert file on disk matches expectation.
- Press `s` with an invalid manually-injected timeout → assert error dialog renders, file unchanged.
- Press `q` while dirty → assert quit-confirm dialog.

Use a temp directory for the config file (via `tree-fs`, already a dev dep).

### 10.6 Integration tests — custom check store

- Create check → file appears with expected content.
- Edit check (no group change) → file content updated, ID matches.
- Edit check (group change) → check moved between files, source file removed if it ends up empty.
- Delete the only check in a file → file removed.
- Two checks in the same group → both live in one file, deleting one leaves the other.
- Reload after manual external edit → in-memory list reflects on-disk state.

### 10.7 Integration tests — load-order fix

- `enabled_groups = [git]`, custom check with `from = my_team` → my_team check is **excluded** (the fix) unless the migration auto-adds `my_team` to `enabled_groups`.
- Migration test: first launch with custom group not in `enabled_groups` → it gets added, `info` log line emitted, second launch is a no-op.
- `ignores_patterns_ids = [my_team:thing]` → custom check with that ID is excluded.

### 10.8 Manual smoke testing

The brainstorming skill mandates browser/UI verification for frontend work; the TUI equivalent is launching the binary in a real terminal and walking through:

- Resize terminal from 200 cols down to 80 cols → preview overlay engages at 100 cols.
- Run on macOS Terminal, iTerm2, Alacritty, and over SSH → no rendering glitches, no panics on resize.
- Run with `TERM=dumb` → graceful "TUI requires a real terminal" error message, exit code != 0.
- Run with `--no-color` env / `NO_COLOR=1` → still readable.

Manual smoke results recorded in the implementation PR description.

### 10.9 CI

- Existing `cargo test` runs all snapshot + unit + integration tests.
- Add `cargo build --no-default-features --features cli,tui` and `--no-default-features --features cli` to CI matrix to verify both feature combinations compile and the no-`tui` fallback path still works.

## 11. Out of scope (explicit)

- Web UI / browser dashboard.
- Native windowed app.
- Mouse support.
- Switching the on-disk format from YAML to JSON.
- Removing existing `config <subcommand>` flags.
- Live-reloading the on-disk file if it changes externally while the TUI is open. (We re-read on launch only; `r` resets to current on-disk state.)
- Internationalization. English only.
- Themes / custom color palettes (use terminal default colors and ratatui's standard palette).

## 12. Risks

- **Snapshot churn.** Visual tweaks will rebuild a lot of snapshots. Mitigation: keep snapshots small/focused; review `insta` diffs carefully.
- **Migration regression.** The custom-check filter fix is a behavior change. The auto-add-group migration mitigates the main case but a user with truly intentional `disabled_groups` covering a custom group could be surprised. Mitigation: log the migration, document in CHANGELOG.
- **Terminal compatibility edge cases** (Windows console, weird `$TERM`s). Mitigation: `crossterm` is the standard cross-platform choice; manual smoke matrix in §10.8.

## 13. Open questions

None at design close — all decisions resolved during brainstorming.
