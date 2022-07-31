# FS Checks:

* `rm -r {PATH}` - This command will delete everything in the path given. A path matching these patterns will be caught: `/`, `*`, `.`, `..` .

* `mv {PATH} /dev/null` - This command transfers given file to the place of the "black hole" virtual device and replaces it. The data will be lost the next time something writes to `/dev/null`.

* `>{FILE NAME}` - This command will flush the contents of the file.

* `chmod -R {MODE} /` - This command changes the permissions of all files in the system. It is likely to compromise its security and make the system unusable, or unable to boot altogether.

* `find -delete` - The `find` command relies heavily on the order of the flags. Therefore, with `-delete` flag as the first one, this command is going to delete everything in your current path, recursively.
