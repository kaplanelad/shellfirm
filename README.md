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
* `git reset --hard` Before hitting the enter key?
* `kubectl delete ns` Stop! you are going to delete a lot of resources
* And many more!

Do you want to learn from other people's mistakes?

`shellfirm` will intercept any risky patterns (predefined or user's custom additions) and will immediately prompt a small challenge that will double verify your action, think of it as a captcha for your terminal.

```bash
$ rm -rf /
#######################
# RISKY COMMAND FOUND #
#######################
* You are going to delete everything in the path.

Solve the challenge: 8 + 0 = ? (^C to cancel)
```

## How does it work?
`shellfirm` will evaluate all the shell commands behind the scenes.
If a risky pattern is detected, you will immediately get a prompt with the relevant warning to verify your command.

## Example
![](./docs/media/example.gif)


## Installation 

### 1. Install via brew
```bash
brew tap kaplanelad/tap && brew install shellfirm
```

Or download the binary file from [releases page](https://github.com/kaplanelad/shellfirm/releases), unzip the file and move to `/usr/local/bin` folder.

### 2. select shell type:

#### If you use Oh My Zsh
* Download zsh plugin:
```bash
curl https://raw.githubusercontent.com/kaplanelad/shellfirm/main/shell-plugins/shellfirm.plugin.zsh --create-dirs -o ${ZSH_CUSTOM:-~/.oh-my-zsh/custom}/plugins/shellfirm/shellfirm.plugin.zsh
```

* Add `shellfirm` to the list of Oh My Zsh plugins when Zsh is loaded(inside ~/.zshrc):
```bash
plugins=(... shellfirm)
```

* :information_source: Open a new shell session


### More supported shells

* [bash](./docs/installation/bash.md)
* [fish](./docs/installation/fishshell.md)

## Verify installation
```
$ mkdir /tmp/shellfirm
$ cd /tmp/shellfirm
$ git reset --hard
```

You should get a `shellfirm` prompt challenge. 

**If you didn't get the prompt challenge:**
1. Make sure the `shellfirm --version` returns a valid response.
2. Make sure that you downloaded the Zsh plugin and added it to the Oh My Zsh plugins in .zshrc.

## Risky commands
We have predefined a baseline of risky groups command that will be enabled by default, these are risky commands that might be destructive.

| Group |  Enabled By Default |
| --- | --- |
| [base](./docs/checks/base.md) | `true` |
| [git](./docs/checks/git.md) | `true` |
| [fs](./docs/checks/fs.md) | `true` |
| [fs-strict](./docs/checks/fs-strict.md) | `false` <br/> `shellfirm config update --check-group fs-strict` |
| [kubernetes](./docs/checks/kubernetes.md) | `false` <br/> `shellfirm config update --check-group kubernetes` |
| [kubernetes-strict](./docs/checks/kubernetes-strict.md) | `false` <br/> `shellfirm config update --check-group kubernetes-strict` |
| [heroku](./docs/checks/heroku.md) | `false` <br/> `shellfirm config update --check-group heroku` |


## Custom checks definition examples

`shellfirm` creates by default a configuration file at `~/.shellfirm/config.yaml`.  Make sure that you only edit `enable` field (in case you want to disable a specific check), all the rest fields are managed by `shellfirm` command (`shellfirm config --help`).

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
    challenge: Default
  - test: "rm.+(-r|-f|-rf|-fr)*"
    method: Regex
    enable: true
    description: "You are going to delete everything in the path."
    from: fs
    challenge: Default
  - test: ">.+/dev/sda"
    method: Regex
    enable: true
    description: "Writing the data directly to the hard disk drive and damaging your file system."
    from: fs
    challenge: Default
  - test: "mv+.*/dev/null"
    method: Regex
    enable: true
    description: "The files will be discarded and destroyed."
    from: fs
    challenge: Default
```

:information_source: To define custom checks that are not part of `shillfirm` baseline, add new checks to the config.yaml with the following field: `from: custom`.
```yaml
  - test: "command to check"
    method: Regex
    enable: true
    description: "Example of custom check."
    from: custom
    challenge: Default
```

:information_source: To define different challenge for a checks you can change the field `challenge: Default` with a [different check](./README.md#change-challenge).


### Add new group checks
```bash
$ shellfirm config update --check-group {risky-command-group-a} {risky-command-group-b}
```

### Remove new group checks
```bash
$ shellfirm config update --check-group {group} {group} --remove
```

### Disable specific checks
Edit the configuration file in `~/.shellfirm/config.yaml` and change the check to `enable:false`.


## Change challenge:
Currently we support 3 different challenges when a risky command is intercepted:
* `Math` - Default challenge which requires you to solve a math question.
* `Enter` - Required only to press `Enter` to continue.
* `Yes` - Required typing `yes` to continue.

You can change the default challenge by running the command:
```bash
$ shellfirm config challenge --challenge Math
```

*At any time you can cancel a risky command by hitting `^C`*

## To Upgrade `shellfirm`
```bash
$ brew upgrade shellfirm
```
* [Add new check group](#add-new-group-checks) or [override configuration with new checks](./docs/config.md#reset) 

## Contributing
Thank you for your interest in contributing! Please refer to [contribution guidelines](./docs/contributing.md) for guidance.

