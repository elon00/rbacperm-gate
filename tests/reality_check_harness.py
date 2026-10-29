"""Legacy smoke entrypoint: execute actual RBAC regression suite, not fake RPC/PQC checks."""
from pathlib import Path
import subprocess
import sys

if __name__ == "__main__":
    root = Path(__file__).resolve().parents[1]
    raise SystemExit(subprocess.call(
        [sys.executable, "-m", "unittest", "discover", "-s", "tests", "-p", "test_*.py", "-v"],
        cwd=root,
    ))
