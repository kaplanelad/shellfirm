# Docker with zsh shell


```sh
run -it eladkaplan/shellfirm:zsh1.0.0 zsh
```

## Build docker image
``` sh
docker build -t shellfirm . && docker run -it shellfirm zsh
```