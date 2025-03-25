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

`shellfirm` will intercept any risky patterns and immediately prompt a small challenge that will double verify your action, think of it as a captcha for your terminal.

```bash
rm -rf /
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


## Setup your shell  

### Install via brew
```bash
brew tap kaplanelad/tap && brew install shellfirm
```

Or download the binary file from [releases page](https://github.com/kaplanelad/shellfirm/releases), unzip the file and move to `/usr/local/bin` folder.

Validate shellfirm installation
```
shellfirm --version
```

## Verify installation
```
mkdir /tmp/shellfirm
cd /tmp/shellfirm
git reset --hard
```

## Select your shell
<details>
<summary>Oh My Zsh</summary>
Download zsh plugin:

```sh
curl https://raw.githubusercontent.com/kaplanelad/shellfirm/main/shell-plugins/shellfirm.plugin.oh-my-zsh.zsh --create-dirs -o ${ZSH_CUSTOM:-~/.oh-my-zsh/custom}/plugins/shellfirm/shellfirm.plugin.zsh
```

Add `shellfirm` to the list of Oh My Zsh plugins when Zsh is loaded(inside ~/.zshrc):

```bash
plugins=(... shellfirm)
```
</details>

<details>
<summary>Bash</summary>
Bash implementation is based on https://github.com/rcaloras/bash-preexec project, which adds a pre-exec hook to catch the command before executing.

```sh
# Download bash-preexec hook functions. 
