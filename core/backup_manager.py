"""
Backup manager
=============

Before LogicBreaker AI writes ANY fix to a real source file, the original is
copied to a timestamped backup directory. This guarantees that a company or
government team can always restore the exact original code -- even after
hundreds of files are patched.

Layout:
    <target>/.logicbreaker_backups/<timestamp>/<original relative path>
    <target>/.logicbreaker_backups/<timestamp>/RESTORE_MANIFEST.json

The manifest records every backed-up file and its original location, plus a
one-line `restore` helper so a human can roll everything back.
"""

import json
import os
import shutil
from datetime import datetime


class BackupManager:
    def __init__(self, target_dir):
        self.target_dir = os.path.abspath(target_dir)
        self.stamp = datetime.now().strftime("%Y%m%d-%H%M%S")
        self.backup_root = os.path.join(self.target_dir, ".logicbreaker_backups", self.stamp)
        self.manifest = []
        self._created = False

    def _ensure_root(self):
        if not self._created:
            os.makedirs(self.backup_root, exist_ok=True)
            self._created = True

    def backup_file(self, abs_path):
        """Copy a file to the backup area before it is modified. Idempotent per
        run (the same file is only backed up once)."""
        abs_path = os.path.abspath(abs_path)
        rel = os.path.relpath(abs_path, self.target_dir)
        if any(e["original"] == rel for e in self.manifest):
            return  # already backed up this run
        if not os.path.exists(abs_path):
            return
        self._ensure_root()
        dest = os.path.join(self.backup_root, rel)
        os.makedirs(os.path.dirname(dest), exist_ok=True)
        shutil.copy2(abs_path, dest)
        self.manifest.append({"original": rel, "backup": os.path.relpath(dest, self.target_dir)})

    def finalize(self):
        """Write the restore manifest. Returns the backup dir, or None if no
        files were backed up."""
        if not self.manifest:
            return None
        self._ensure_root()
        manifest_path = os.path.join(self.backup_root, "RESTORE_MANIFEST.json")
        with open(manifest_path, "w", encoding="utf-8") as f:
            json.dump({
                "created": self.stamp,
                "target": self.target_dir,
                "files": self.manifest,
                "how_to_restore": "Copy each 'backup' file back over its 'original' path, "
                                  "or run: python -m core.backup_manager restore "
                                  f'"{self.backup_root}"',
            }, f, indent=2)
        return self.backup_root

    @property
    def count(self):
        return len(self.manifest)


def restore(backup_dir):
    """Restore every file recorded in a backup dir's manifest."""
    manifest_path = os.path.join(backup_dir, "RESTORE_MANIFEST.json")
    with open(manifest_path, "r", encoding="utf-8") as f:
        data = json.load(f)
    target = data["target"]
    restored = 0
    for entry in data["files"]:
        src = os.path.join(target, entry["backup"])
        dst = os.path.join(target, entry["original"])
        if os.path.exists(src):
            os.makedirs(os.path.dirname(dst), exist_ok=True)
            shutil.copy2(src, dst)
            restored += 1
    return restored


if __name__ == "__main__":
    import sys
    if len(sys.argv) == 3 and sys.argv[1] == "restore":
        n = restore(sys.argv[2])
        print(f"Restored {n} file(s) from {sys.argv[2]}")
    else:
        print("Usage: python -m core.backup_manager restore <backup_dir>")
