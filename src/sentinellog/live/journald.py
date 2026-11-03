"""Report whether this VM has a readable journal. Log text is not passed to a command."""

import shutil
import subprocess
from functools import lru_cache


@lru_cache
def journald_availability() -> tuple[bool, str]:
    binary = shutil.which("journalctl")
    if binary is None:
        return False, "journalctl is not installed."
    try:
        result = subprocess.run(
            [binary, "-n", "1", "--no-pager", "-o", "cat"],
            capture_output=True,
            text=True,
            timeout=5,
            check=False,
        )
    except (OSError, subprocess.TimeoutExpired):
        return False, "journalctl is installed but could not be run."
    combined = f"{result.stdout}\n{result.stderr}".lower()
    if "no journal files" in combined or "no entries" in combined or not result.stdout.strip():
        return False, "journalctl is installed but this VM has no journal files."
    if result.returncode != 0:
        return False, "journalctl is installed but the journal is not readable."
    return True, "journalctl can read the local journal."
