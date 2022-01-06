# FS Checks:

* `rm -rf /` - This command will delete anything under `/` or `*` directory.  

* `mv {PATH} /dev/null` - This command transfers the given path to a virtual device that does not exist. Therefore, data will be completely lost.

* `>{FILE NAME}` - The command is used to flush the content of file.

* `chmod -R {MODE} /` - The command allows all users to read, write, and execute all files on the system, which compromises security. Additionally, certain systems may malfunction if the permissions are too open and prevent the system from booting.

* `find -delete` - You may have been confused with `-delete` flag order. this command going to delete all find files in your current path.
