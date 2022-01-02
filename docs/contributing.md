# Contributing

You are more than welcome to help the community with the following options

## Add more risky commands

Add more risky command patters to one of the check group in `checks` folder or add a bew group and open a PR.


### Test new command
1. Add new check to one of the groups/create new group.
2. Run `pre-command` command with `-t`
```bash
$ shellfirm pre-command --command 'rm -rf' -t

---
is: rm.+(-r|-f|-rf|-fr)*
method: Regex
enable: true
description: You are going to deletes everything in the path.
```
You will get all finding checks to STDOUT

## Open issues

Open an issue with your problems/requirements that you think will helpful.

## Run it locally
Run it locally by running the command:
```bash
cargo run -- pre-command --command "git reset"
```

## Test
See all tests and more validation by running the command:
```bash
make help
```