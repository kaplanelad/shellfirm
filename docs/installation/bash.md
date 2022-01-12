# Bash Installation

Bash implementation is based on https://github.com/rcaloras/bash-preexec project, which adds a pre-exec hook to catch the command before executing.

```bash
# Download bash-preexec hook functions. 
curl https://raw.githubusercontent.com/rcaloras/bash-preexec/master/bash-preexec.sh -o ~/.bash-preexec.sh

# Source our file at the end of our bash profile (e.g. ~/.bashrc, ~/.profile, or ~/.bash_profile)
echo '[[ -f ~/.bash-preexec.sh ]] && source ~/.bash-preexec.sh' >> ~/.bashrc

# Download shellfirm pre-exec function
curl https://raw.githubusercontent.com/kaplanelad/shellfirm/main/shellfirm.plugin.sh -o ~/.shellfirm-plugin.sh

# Load pre-exec command on shell initialized
echo 'source ~/.shellfirm-plugin.sh' >> ~/.bashrc
```
