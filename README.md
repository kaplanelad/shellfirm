# shellfirm

<div align="center">
<h1>Opppppsss <b>you</b> did it again? :scream: :scream: :cold_sweat:</h1>
</div>
Protect yourself from yourself!

* `rm -rf *`
* `git reset --hard` before saving?
* `kubectl delete ns` which going to delete all resources under this namespace?
* And more!


Do you want to learn from people that made those mistakes??

`shellfirm` will intercept any risky patterns (default or defined by you) and prompt you a small challenge for double verification, kinda like a captcha for your terminal.

```bash
$ rm -rf /
#######################
# RISKY COMMAND FOUND #
#######################
* You are going to delete everything in the path.

Solve the challenge: 8 + 0 = ? (^C to cancel)
```

## How it works?
`shellfirm` evaluate all shell command behind the scene. 
If a risky pattern is detected, you will get a prompt with a warning and double verification will requests.


## Example
![](./docs/media/example.gif)


## Installation 
* Install via brew
```bash
brew tap kaplanelad/tap && brew install shellfirm
```

### Oh My Zsh

* Download zsh plugin:
```bash
curl https://raw.githubusercontent.com/kaplanelad/shellfirm/main/shellfirm.plugin.zsh --create-dirs -o ${ZSH_CUSTOM:-~/.oh-my-zsh/custom}/plugins/shellfirm/shellfirm.plugin.zsh

```
* Add the `shellfirm` to the list of plugins for Oh My Zsh to load (inside ~/.zshrc):
```bash
plugins=(... shellfirm)
```


## Risky command:
| Group |  Enable By Default |
| --- | --- |
| [base](./docs/checks/base.md) | `true` |
| [git](./docs/checks/git.md) | `true` |
| [fs](./docs/checks/fs.md) | `true` |
| [fs-strict](./docs/checks/fs-strict.md) | `false` <br/> `shellfirm config update --check-group fs-strict` |
| [kubernetes](./docs/checks/kubernetes.md) | `false` <br/> `shellfirm config update --check-group kubernetes` |


## Checks examples:

After installing `shellfirm` creates config file in the path: `~/.shellfirm/config.yaml`. make sure that you not editing this file. to add/remove checks you can mange via `shellfirm config --help`

```yaml
challenge: Math # Math, Enter, Yes

includes: 
  - base
  - fs
  - git

checks:
  - test: git reset
    method: Contains
    enable: true
    description: "This command going to reset all your local changes."
    from: git
  - test: "rm.+(-r|-f|-rf|-fr)*"
    method: Regex
    enable: true
    description: "You are going to delete everything in the path."
    from: fs
  - test: ">.+/dev/sda"
    method: Regex
    enable: true
    description: "Writing the data directly to the hard disk drive and damaging your file system."
    from: fs
  - test: "mv+.*/dev/null"
    method: Regex
    enable: true
    description: "The files will be discarded and destroyed."
    from: fs
```

:information_source: to define custom check (that not include int the `shillfirm` check) add new check to config.yaml file with `from: custom`.
```yaml
  - test: "special check"
    method: Regex
    enable: true
    description: "Example of custom check."
    from: custom
```

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


## Updates
* Update `shellfirm`:
```bash
$ brew upgrade shellfirm
```
* [Add new check group](#add-new-group-checks) or [override configuration with new checks](./docs/config.md#reset) 

## Contributing
See the [contributing](./docs/contributing.md) directory for more developer documentation.
