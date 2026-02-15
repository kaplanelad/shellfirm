# shellfirm hook for fish — intercepts Enter via key binding
# https://github.com/kaplanelad/shellfirm

if not command -v shellfirm &> /dev/null
    echo "`shellfirm` binary is missing. see installation guide: https://github.com/kaplanelad/shellfirm#installation."
    exit 1
end

function _shellfirm_check
    set -l cmd (commandline)
    if test -z "$cmd"; or string match -q '*shellfirm pre-command*' -- $cmd
        commandline -f execute
        return
    end
    stty sane
    shellfirm pre-command -c "$cmd"
    if test $status -eq 0
        commandline -f execute
    else
        commandline -f repaint
    end
end

bind \r _shellfirm_check
# Also bind in vi insert mode if active
bind -M insert \r _shellfirm_check 2>/dev/null
