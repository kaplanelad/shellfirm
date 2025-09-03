# FS Checks:

- `rm -r {PATH}` - This command will delete everything in the path given. A path matching these patterns will be caught: `/`, `*`, `.`, `..` .

- `mv {PATH} /dev/null` - This command transfers given file to the place of the "black hole" virtual device and replaces it. The data will be lost the next time something writes to `/dev/null`.

- `>{FILE NAME}` - This command will flush the contents of the file.

- `chmod -R {MODE} /` - This command changes the permissions of all files in the system. It is likely to compromise its security and make the system unusable, or unable to boot altogether.

- `find -delete` - The `find` command relies heavily on the order of the flags. Therefore, with `-delete` flag as the first one, this command is going to delete everything in your current path, recursively.

- `dd of=/dev/{BLOCK_DEVICE}` - This command writes directly to a block device, which could overwrite your disk.

- `mkfs {DEVICE}` - This command formats a device, erasing all data on it.

- `parted {DEVICE}` - This command modifies disk partitions, which could erase all data on the disk.

- `fdisk {DEVICE}` - This command modifies disk partitions, which could erase all data on the disk.

- `sfdisk {DEVICE}` - This command modifies disk partitions, which could erase all data on the disk.

- `dd conv=notrunc of={BLOCK_DEVICE}` - This command writes to a specific sector of the disk, which could corrupt data.

- `gdisk {DEVICE}` - This command modifies GPT disk partitions, which could erase all data on the disk.

- `partprobe {DEVICE}` - This command informs the OS of partition table changes, which could affect mounted partitions.

- `blockdev {DEVICE}` - This command modifies block device parameters, which could affect disk operations.

- `mount {DEVICE}` - This command mounts a device, which could affect system stability.

- `lvremove {VOLUME}` - This command removes logical volumes or volume groups, deleting all data.

- `dump {DEVICE}` - This command backs up or restores a filesystem, which could affect system stability.

- `cryptsetup {DEVICE}` - This command encrypts or decrypts a device, which could affect data accessibility.

- `rm {PATH}` - Detects any deletion operation when the file exists (safer prompt for common deletes).

- `rmdir {DIRECTORY}` - Detects folder deletion operations when the folder exists.

- `chmod {MODE}` - Detects risky permission changes such as 777/000/666.
