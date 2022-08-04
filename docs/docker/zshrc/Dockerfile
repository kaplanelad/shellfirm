
FROM ubuntu:20.04

RUN apt-get update && apt-get upgrade -y && apt install curl jq xz-utils vim -y

RUN apt-get install -y zsh

RUN usermod -s $(which zsh) root

RUN mkdir ~/.config

# Download shellfirm pre-exec function
RUN curl https://raw.githubusercontent.com/kaplanelad/shellfirm/main/shell-plugins/shellfirm.plugin.sh -o /root/.shellfirm-plugin.sh

# doenload shellfirm
RUN curl https://api.github.com/repos/kaplanelad/shellfirm/releases/latest | jq -r .tag_name | { read version; curl -L https://github.com/kaplanelad/shellfirm/releases/download/${version}/shellfirm-${version}-x86_64-linux.tar.xz -o /tmp/shellfirm.tar.xz; } && \
    cd /tmp && \
    tar xf shellfirm.tar.xz && \
    cd $(ls -d */|head -n 1) && \
    cp shellfirm /usr/local/bin

# Load pre-exec command on shell initialized
RUN echo 'source /root/.shellfirm-plugin.sh' >> ~/.zshrc