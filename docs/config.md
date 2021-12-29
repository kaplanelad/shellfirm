# Config

When you install `shellfirm` the first time it creates a new config file in the home directory in the path: ~/.shellfirm/config.yaml.
The main configuration file manage in [config.yaml](../src/config.yaml). 
You can always change your config file content and the `shellfirm` will never change it back. 


# Config
| Parameter | Description | Values |
| --- | --- | --- |
| `challenge` | The way that you want to solve the challenge when risky command detected | `Math`, `Enter`, `YesNo` |
| `checks[].is` | The value of the check | `String` |
| `checks[].method` | How to make the check | `Contains`, `Regex`, `StartWith` |
| `checks[].enable` | Enable disable the check | `true`, `false` |
| `checks[].description` | Prompt description when risky command directed | `String` |


# Update config file

Option one is to override the current configuration:
```bash
shellfirm update-configuration --behavior override
```

Option two is to keep your configuration and still enjoy the updated checks by running the command
```bash
shellfirm update-configuration --behavior only-diff
```