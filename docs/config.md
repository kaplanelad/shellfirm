# Config

When you install `shellfirm` the first time it creates a new settings file under your config directory. The path will typically be:

- macOS/Linux: `~/.config/shellfirm/settings.yaml` (if `~/.shellfirm` does not already exist)
- Legacy compatibility: if `~/.shellfirm` exists, the file remains under `~/.shellfirm/settings.yaml`

You can always change your settings, and `shellfirm` won’t overwrite them.
[Read here how to add and test a new command](../readme.md#custom-checks-definition-examples)

## Settings schema

| Field                  | Description                                    | Values                                       |
| ---------------------- | ---------------------------------------------- | -------------------------------------------- |
| `challenge`            | Interactive challenge shown for risky commands | `Math`, `Enter`, `Yes`, `Block`              |
| `includes_severities`  | Severities that are enforced                   | List of: `Low`, `Medium`, `High`, `Critical` |
| `ignores_patterns_ids` | Rule IDs to ignore (will not prompt)           | List of rule IDs                             |
| `deny_patterns_ids`    | Rule IDs to block immediately                  | List of rule IDs                             |

## CLI reference

Global option:

- `--log {off|trace|debug|info|warn|error}`: Set logging level (default: `info`)

Subcommands:

- `pre-command --command <string> [--test]`

  - Validates the provided command against active checks.
  - `--test`: print matched checks as YAML and exit with success.

- `config update-severity`

  - Interactively choose which severities are enforced.

- `config challenge`

  - Interactively select the default challenge type.

- `config ignore`

  - Interactively manage ignored rule IDs.

- `config deny`

  - Interactively manage denied rule IDs.

- `config path`

  - Print the absolute path to the settings file.

- `config edit`

  - Open the settings file in your editor (`$EDITOR`/`$VISUAL`), or system opener.

- `config reset`
  - Reset the settings file. Offers to back up the current file.
