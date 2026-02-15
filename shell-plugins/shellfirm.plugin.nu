# Protect yourself from yourself!
# shellfirm will intercept any risky patterns and prompt you a small challenge for double verification.
# This hook triggers before every command execution and passes it to `shellfirm` for pattern checking.
# Read more: https://github.com/kaplanelad/shellfirm#how-it-works

# Add the following to your Nushell config (run: `config nu` to edit):
$env.config.hooks.pre_execution = (
    $env.config.hooks.pre_execution | append {||
        let cmd = (commandline)
        if ($cmd | str trim | is-empty) {
            return
        }
        if ($cmd | str contains "shellfirm pre-command") {
            return
        }
        let result = (do { shellfirm pre-command -c $cmd } | complete)
        if $result.exit_code != 0 {
            commandline edit ""
        }
    }
)
