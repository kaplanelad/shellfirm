# FS-Strict Checks

:warning: Make sure that the `fs` group is also enabled :warning:

- `rm {OPTIONS} {FILES}` - This command detects any deletion operation and prompts for confirmation.

- `rmdir {DIRECTORY}` - This command detects any folder deletion operation and prompts for confirmation.

- `chmod {OPTIONS} {FILES}` - This command detects any permissions change operation and prompts for confirmation.

- `echo "some text" > file.txt` - This command detects file text override operations and prompts for confirmation.
