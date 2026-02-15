# shellfirm hook for zsh — intercepts Enter via the accept-line widget
# https://github.com/kaplanelad/shellfirm

if ! command -v shellfirm &> /dev/null; then
    echo "\`shellfirm\` binary is missing. see installation guide: https://github.com/kaplanelad/shellfirm#installation."
    return
fi

shellfirm-pre-command() {
    if [[ -z "${BUFFER}" || "${BUFFER}" == *"shellfirm pre-command"* ]]; then
        zle .accept-line
        return
    fi
    shellfirm pre-command -c "${BUFFER}"
    if [[ $? -eq 0 ]]; then
        zle .accept-line
    fi
}
zle -N accept-line shellfirm-pre-command
