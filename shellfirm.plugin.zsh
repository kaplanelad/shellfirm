
# Protect yourself from yourself!
# shellfirm will intercept any risky patterns and prompt you a small challenge for double verification.
# `printc` funciton will trigger (as hook event) on any terminal command. the command will pass to `shellfirm` binary for check if 
# the command match match to one of the patters. read more: https://github.com/kaplanelad/shellfirm#how-it-works 


# Checks if shellfirm binary is accessible 
shellfirm --version >/dev/null 2>&1
if [ "$?" != 0 ]; then
    # show this message to the user and don't register to terminal hook
    # we want to show the user that he not protected with `shellfirm`
    echo "`shellfirm` binarry is missing. see installation guide in link: https://github.com/kaplanelad/shellfirm#installation."
    return
fi

function shellfirm-pre-command () {
    shellfirm  pre-command --command "${1}"
}

autoload -Uz add-zsh-hook
add-zsh-hook preexec shellfirm-pre-command