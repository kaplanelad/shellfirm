# Config

When you install `shellfirm` the first time it creates a new config file in the home directory in the path: `~/.shellfirm/config.yaml`.

You can always change your config file content and the `shellfirm` will never change it back. 
[read here how to add and test new command](../readme.md#custom-checks-definition-examples)


## Config
| Parameter | Description | Values |
| --- | --- | --- |
| `challenge` | The way that you want to solve the challenge when risky command detected | `Math`, `Enter`, `Yes` |
| `includes` | List of group checks. | `list` |
| `checks[].test` | The value of the check | `String` |
| `checks[].method` | How to make the check | `Contains`, `Regex`, `StartWith` |
| `checks[].enable` | Enable/disable | `true`, `false` |
| `checks[].description` | Prompt description when a risky command detected | `String` |
| `checks[].from` | Group name | `String` |


## Update config file

### Add new groups
```bash
$ shellfirm config update --check-group {group} {group}
```

### Remove groups
```bash
$ shellfirm config update --check-group {group} {group} --remove
```

### Reset 
```bash
$ shellfirm config reset
```