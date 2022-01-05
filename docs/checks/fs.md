# FS Checks:

* `rm -rf /` - deletes everything it possibly can. The check is regex and will trigger on multiple combination like order the flag and `*` instead of `/`.

* `mv {PATH} /dev/null` - This command transfers the given path to a virtual device that does not exist. Therefore, data will be completely lost.

* `>{FILE NAME}` - The command is used to flush the content of file.

* `chmod -R {MODE} /` - The command above allows all users to read, write, and execute all files on the system, which compromises security. Additionally, certain systems may malfunction if the permissions are too open and prevent the system from booting.

* `find -delete` - You may have been confused with `-delete` flag order. this command going to delete all find files in your current path.
