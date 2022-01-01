# Config

When you install `shellfirm` the first time it creates a new config file in the home directory in the path: `~/.shellfirm/config.yaml`.
The main configuration file manage in [config.yaml](../src/config.yaml). 

You can always change your config file content and the `shellfirm` will never change it back. 
[read here how to add and test new command](./contributing.md#test-new-command)


# Config
| Parameter | Description | Values |
| --- | --- | --- |
| `challenge` | The way that you want to solve the challenge when risky command detected | `Math`, `Enter`, `Yes` |
| `includes` | List of group checks. | `list` |
| `checks[].is` | The value of the check | `String` |
| `checks[].method` | How to make the check | `Contains`, `Regex`, `StartWith` |
| `checks[].enable` | Enable disable the check | `true`, `false` |
| `checks[].description` | Prompt description when risky command directed | `String` |
| `checks[].from` | Group name | `String` |


# Update config file

Adding new groups:
```bash
$ shellfirm config update --check-group {group} {group}
```

Remove groups
```bash
$ shellfirm config update --check-group {group} {group} --remove
```

Reset 
```bash
$ shellfirm config reset
```