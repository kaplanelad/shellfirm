# shellfirm

<div align="center">
<h1>Opppppsss <b>you</b> did it again? :scream: :scream: :cold_sweat:</h1>
</div>
Protect yourself from yourself!

* `rm -rf *`
* `git reset --hard` before saving?
* Do you want to learn from people that made those mistakes?

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

checks:
  - is: git reset
    method: Contains
    enable: true
    description: "This command going to reset all your local changes."
  - is: "rm.+(-r|-f|-rf|-fr)*"
    method: Regex
    enable: true
    description: "You are going to deletes everything in the path."
  - is: ">.+/dev/sda"
    method: Regex
    enable: true
    description: "Writing the data directly to the hard disk drive and damaging your file system."
  - is: "mv+.*/dev/null"
    method: Regex
    enable: true
    description: "The files will be discarded and destroyed."
```



## Live example
TODO... add a gif with action

## Installation 
TODO...


## See all existing risky command:
from master repository: Go to [config.yaml file](./src/config.yaml)

After installing `shellfirm` tool the config stored in the path: `~/.shellfirm/config.yaml`

## Change challenge
currently we supporting 3 different challenges when a command is detected:
* `Math` - Default challenge which requires you to solve a math question.
* `Enter` - Requite only `Enter` to continue.
* `Yes` - Requite `yes` to continue.

You can change the default challenge in [config.yaml file](./src/config.yaml).

*At any time you can exit with the challenge by `^C`*

## Version update
TODO....
To update the config file with more checks [go here](./docs/config.md#Update-config-file)


## Contributing
See the [contributing](../docs/CONTRIBUTING.MD) directory for more developer documentation.