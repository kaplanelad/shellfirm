# Contributing

You are more than welcome to help the community with the following options

## Add more risky commands

Add more risky command patterns to one of the check groups in the `checks` folder or create a new group and open a PR.

### Create and enable a new check group locally
1. Add the new group as a `yaml` file in the [shellfirm/checks](../shellfirm/checks) folder.
2. Add documentation for the newly-created group (and checks) in [docs/checks](../docs/checks).
3. Add it to the [README.md](../README.md#risky-commands) documentation.
4. Enable the group by running the command
```bash
cargo run -- config update new-group
```

### Test new command
1. Add new check to one of the groups.
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