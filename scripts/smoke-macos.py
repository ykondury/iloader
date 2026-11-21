"""Run only an application startup check on a disposable macOS runner."""

import json
import platform
import subprocess
import sys
from pathlib import Path


app, output = map(Path, sys.argv[1:])
output.mkdir(parents=True, exist_ok=True)
result = {"architecture": platform.machine(), "platform": platform.platform(),
          "survived_10_seconds": False, "apple_id_login_verified": False}
with (output / "startup.log").open("wb") as log:
    process = subprocess.Popen([str(app / "Contents/MacOS/iloader")], stdout=log, stderr=subprocess.STDOUT)
    try:
        result["early_exit_code"] = process.wait(timeout=10)
    except subprocess.TimeoutExpired:
        result["survived_10_seconds"] = True
    finally:
        if process.poll() is None:
            process.terminate()
            try:
                process.wait(timeout=5)
            except subprocess.TimeoutExpired:
                process.kill()
                process.wait(timeout=5)
(output / "startup.json").write_text(json.dumps(result, indent=2) + "\n", encoding="utf-8")
print(json.dumps(result, indent=2))
raise SystemExit(0 if result["survived_10_seconds"] else 1)
