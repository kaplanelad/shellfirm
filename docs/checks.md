# Checks

Here you can find the list of command that should trigger 


## base

* `:(){ :|: & };:` - This short line defines a shell function that creates new copies of itself. The process continually replicates itself, and its copies continually replicate themselves, quickly taking up all your CPU time and memory
* `history | bash` - Going to execute all history commands


## fs

* `rm -rf /` - deletes everything it possibly can. The check is regex and will trigger on multiple combination like order the flag and `*` instead of `/`. 
* `mv {PATH} /dev/null` - This command transfers the given path to a virtual device that does not exist. Therefore, data will be completely lost.
* `>{FILE NAME}` - The command is used to flush the content of file.
* `chmod -R {MODE} /` - The command above allows all users to read, write, and execute all files on the system, which compromises security. Additionally, certain systems may malfunction if the permissions are too open and prevent the system from booting.
* `find -delete` - You may have been confused with `-delete` flag order. this command going to delete all find files in your current path.

## git

* `git reset` - Reset current HEAD to the specified state. you can lose your changes if the changes not committed. 

## kubernetes

* `kubectl delete ns` - This deletes everything under the namespace!. The check is regex and will trigger on multiple combination like `k delete ns` / `kubectl -n delete` and any delete combination.