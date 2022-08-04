
FROM ubuntu:20.04

RUN apt-get update && apt-get upgrade -y && apt install curl jq xz-utils -y

RUN mkdir ~/.config

RUN curl https://raw.githubusercontent.com/rcaloras/bash-preexec/master/bash-preexec.sh -o /root/.bash-preexec.sh

# Source our file at the end of our bash profile (e.g. ~/.bashrc, ~/.profile, or ~/.bash_profile)
RUN echo '[[ -f ~/.bash-preexec.sh ]] && source ~/.bash-preexec.sh' >> ~/.bashrc

# Download shellfirm pre-exec function
RUN curl https://raw.githubusercontent.com/kaplanelad/shellfirm/main/shell-plugins/shellfirm.plugin.sh -o /root/.shellfirm-plugin.sh

# doenload shellfirm
RUN curl https://api.github.com/repos/kaplanelad/shellfirm/releases/latest | jq -r .tag_name | { read version; curl -L https://github.com/kaplanelad/shellfirm/releases/download/${version}/shellfirm-${version}-x86_64-linux.tar.xz -o /tmp/shellfirm.tar.xz; } && \
    cd /tmp && \
    tar xf shellfirm.tar.xz && \
    cd $(ls -d */|head -n 1) && \
    cp shellfirm /usr/local/bin

# Load pre-exec command on shell initialized
RUN echo 'source /root/.shellfirm-plugin.sh' >> ~/.bashrc
RUN echo 'echo "?"' >> ~/.bashrc