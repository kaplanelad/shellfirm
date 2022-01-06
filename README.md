# shellfirm

<div align="center">
<h1>Opppppsss <b>you</b> did it again? :scream: :scream: :cold_sweat:</h1>
</div>

How do I save myself from myself?
* `rm -rf *`
* `git reset --hard` before hitting the enter key?
* `kubectl delete ns` Stop! you are going to delete a lot of resources
* And many more!

Do you want to learn from other people mistakes?

`shellfirm` will intercept any risky patterns (defined by defaul or any other user custom additions) it will immediately prompt a small challenge that will double verify your action think of a captcha for your terminal.

```bash
$ rm -rf /
#######################
# RISKY COMMAND FOUND #
#######################
* You are going to delete everything in the path.

Solve the challenge: 8 + 0 = ? (^C to cancel)
```

## How dose it it work?
`shellfirm` will evaluate all shell commands behind the scene. 
If a risky pattern is detected, you will immediately get a prompt with the relevant a warning ato verify you and approve your risky actions.


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
* Add `shellfirm` as part of the list of Oh My Zsh plugins when Zsh is loaded(inside ~/.zshrc):
```bash
plugins=(... shellfirm)
```


## Risky commands
| Group |  Enabled By Default |
| --- | --- |
| [base](./docs/checks/base.md) | `true` |
| [git](./docs/checks/git.md) | `true` |
| [fs](./docs/checks/fs.md) | `true` |
| [fs-strict](./docs/checks/fs-strict.md) | `false` <br/> `shellfirm config update --check-group fs-strict` |
| [kubernetes](./docs/checks/kubernetes.md) | `false` <br/> `shellfirm config update --check-group kubernetes` |


## Custom checks definition examples:

`shellfirm` create by default a configuration file at `~/.shellfirm/config.yaml`.  Make sure that you edit only `enable` field (in case you want to disable a specific check), all the rest check manage by `shellfirm` command (`shellfirm config --help`).

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

:information_source: To define custom checks that are not part of the baseline of `shillfirm` add new checks to the config.yaml with the following field: `from: custom`.
```yaml
  - test: "special check"
    method: Regex
    enable: true
    description: "Example of custom check."
    from: custom
```

### Add new group checks:
```bash
$ shellfirm config update --check-group {risky-command-group-a} {risky-command-group-b}
```

### Remove new group checks:
```bash
$ shellfirm config update --check-group {group} {group} --remove
```

### Disable specific check
Edit configuration file in `~/.shellfirm/config.yaml` and change the check to `enable:false`.


## Change challenge:
currently we support 3 different challenges when a risky command is intercepted:
* `Math` - Default challenge which requires you to solve a math question.
* `Enter` - Requite only to press `Enter` to continue.
* `Yes` - Requite to type `yes` to continue.

You can change the default challenge by running the command:
```bash
$ shellfirm config challenge --challenge Math
```

*At any time you can cancel risky command by hitting `^C`*


## Upgrades
* Update `shellfirm`:
```bash
$ brew upgrade shellfirm
```
* [Add new check group](#add-new-group-checks) or [override configuration with new checks](./docs/config.md#reset) 

## Contributing
See the [contributing](./docs/contributing.md) directory for more developer documentation.
