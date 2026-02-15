# Protect yourself from yourself!
# shellfirm will intercept any risky patterns and prompt you a small challenge for double verification.
# This hook triggers before every command execution and passes it to `shellfirm` for pattern checking.
# Read more: https://github.com/kaplanelad/shellfirm#how-it-works

# Add the following to ~/.xonshrc:

import subprocess
import shutil

# Checks if shellfirm binary is accessible
if shutil.which("shellfirm") is None:
    print("`shellfirm` binary is missing. See installation guide: https://github.com/kaplanelad/shellfirm#installation.")
else:
    @events.on_precommand
    def _shellfirm_precommand(cmd, **kwargs):
        if not cmd or not cmd.strip():
            return
        if "shellfirm pre-command" in cmd:
            return
        result = subprocess.run(
            ["shellfirm", "pre-command", "-c", cmd],
            capture_output=True,
        )
        if result.returncode != 0:
            raise PermissionError("Command blocked by shellfirm")
