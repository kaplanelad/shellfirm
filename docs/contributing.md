# Contributing

You are more than welcome to help the community with the following options

## Add more risky commands

Add more risky command patterns to one of the check groups in the `checks` folder or add a bew group and open a PR.


### Test new command
1. Add new check to one of the groups/create new group.
2. Run `pre-command` command with `-t`
```bash˜
$ shellfirm pre-command --command 'rm -rf' -t

---
is: rm.+(-r|-f|-rf|-fr)*
method: Regex
enable: true
description: You are going to delete everything in the path.
```

All the findings will be directed to STDOUT

## Open issues

Feel free to open any issues you have encountered

## Run it locally
Run it locally by running the command:
```bash
cargo run -- pre-command --command "git reset"
```

## Make file options
```bash
make help
```