# shellfirm

<div align="center">
<h1>Opppppsss <b>you</b> did it again? :scream: :scream: :cold_sweat:</h1>
</div>
Protect yourself from yourself!

* `rm -rf *`
* `git reset --hard` before saving?
* `kubectl delete ns` i'm want to delete all resources under this namespace?


Or you just o you want to learn from people that made those mistakes?

`shellfirm` will intercept any risky patterns (default or defined by you) and prompt you a small challenge for double verification, kinda like a captcha for your terminal.

```bash
$ rm -rf /
#######################
# RISKY COMMAND FOUND #
#######################
* You are going to deletes everything in the path

Solve the challenge: 8 + 0 = ? (^C to cancel)
```

## How it works?
`shellfirm` evaluate all shell command behind the scene. 
If a risky pattern is detected, you will get a prompt with a warning and double verification will requests.

### Checks examples:
```yaml
challenge: Math # Math, Enter, Yes

includes: 
  - base
  - fs
  - git

checks:
  - is: git reset
    method: Contains
    enable: true
    description: "This command going to reset all your local changes."
    from: git
  - is: "rm.+(-r|-f|-rf|-fr)*"
    method: Regex
    enable: true
    description: "You are going to deletes everything in the path."
    from: fs
  - is: ">.+/dev/sda"
    method: Regex
    enable: true
    description: "Writing the data directly to the hard disk drive and damaging your file system."
    from: fs
  - is: "mv+.*/dev/null"
    method: Regex
    enable: true
    description: "The files will be discarded and destroyed."
    from: fs
```

:information_source: to define custom check (that not include int the `shillfirm` check) make the `from` with `custom`
```yaml
  - is: "special check"
    method: Regex
    enable: true
    description: "Example of custom check."
    from: custom
```

## Live example
TODO... add a gif with action

## Installation 
* brew command
* Download zsh plugin:
```bash
curl  https://raw.githubusercontent.com/kaplanelad/shellfirm/main/shellfirm.plugin.zsh --create-dirs -o ${ZSH_CUSTOM:-~/.oh-my-zsh/custom}/plugins/shellfirm/shellfirm.plugin.zsh
```
* Finally, add the shellfirm as the plugin in your .zshrc file as:
```bash
plugins=(... shellfirm)
```

## Updates
TODO...

## Risky command:
| Group | Path | Enabled by default |
| --- | --- | --- |
| `base` | [base.yaml file](./checks/base.yaml) | `true` |
| `git` | [git.yaml file](./checks/git.yaml) | `true` |
| `fs` | [fs.yaml file](./checks/fs.yaml) | `true` |

After installing `shellfirm` tool the config stored in the path: `~/.shellfirm/config.yaml`

You can always manage your out risky command:

### Add new group checks:
```bash
$ shellfirm config update --check-group {group} {group}
```

### Remove new group checks:
```bash
$ shellfirm config update --check-group {group} {group} --remove
```

### Disable specific check
Edit configuration file in `~/.shellfirm/config.yaml` and change the check to `enable:false`.


## Change challenge
currently we supporting 3 different challenges when a command is detected:
* `Math` - Default challenge which requires you to solve a math question.
* `Enter` - Requite only `Enter` to continue.
* `Yes` - Requite `yes` to continue.

You can change the default challenge by running the command:
```bash
$ shellfirm config challenge --challenge Math
```

*At any time you can exit with the challenge by `^C`*

## Contributing
See the [contributing](../docs/CONTRIBUTING.MD) directory for more developer documentation.