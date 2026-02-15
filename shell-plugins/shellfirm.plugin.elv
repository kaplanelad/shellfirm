# Protect yourself from yourself!
# shellfirm will intercept any risky patterns and prompt you a small challenge for double verification.
# This hook triggers before every command execution and passes it to `shellfirm` for pattern checking.
# Read more: https://github.com/kaplanelad/shellfirm#how-it-works

# Add the following to ~/.config/elvish/rc.elv:

# Checks if shellfirm binary is accessible
if (not ?(which shellfirm &>/dev/null)) {
    echo "shellfirm binary is missing. See installation guide: https://github.com/kaplanelad/shellfirm#installation."
} else {
    set edit:insert:binding[Enter] = {
        var cmd = (edit:current-command)
        if (eq $cmd "") {
            edit:smart-enter
            return
        }
        if (str:contains $cmd "shellfirm pre-command") {
            edit:smart-enter
            return
        }
        try {
            shellfirm pre-command -c $cmd 2>/dev/null
            edit:smart-enter
        } catch {
            edit:redraw &full=$true
        }
    }
}
