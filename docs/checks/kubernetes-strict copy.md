# Kubernetes-Strict Checks:

:warning: make sure that `fs` group also enabled :warning: 

* Detect any deletion (`rm`) command.  

* Detect and permissions changes (`chmod`) command.

* Detect and file text override `some text > file.txt`.