shellfirm-pre-command () {
    if [[ "${BUFFER}" == *"shellfirm pre-command"* ]]; then
        return
    fi
    shellfirm pre-command --command "${BUFFER}"
    zle .accept-line
}
zle -N accept-line shellfirm-pre-command