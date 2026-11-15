"""Non-destructive kernel inventory only; never executes a model or attack."""
import ctypes
import datetime as dt
import hashlib
import json
import pathlib
import subprocess
import sys
import argparse
import os

ROOT = pathlib.Path(__file__).resolve().parents[1]
KERNEL = pathlib.Path(r"C:\Program Files\Wolfram Research\Wolfram\15.0\SystemFiles\Kernel\Binaries\Windows-x86-64\WolframKernel.exe")

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--run", action="store_true")
    parser.add_argument("--label", default="kernel")
    args = parser.parse_args()
    if not args.label.replace("-", "").isalnum():
        raise SystemExit("Invalid output label")
    if sys.platform != "win32" or ctypes.windll.shell32.IsUserAnAdmin():
        raise SystemExit("Discovery requires a non-administrator Windows process.")
    target = ROOT / "results" / "discovery"
    target.mkdir(parents=True, exist_ok=True)
    if (target / (args.label + ".json")).exists() or (target / (args.label + "-runtime.json")).exists():
        raise SystemExit("Use a new --label; existing evidence is never overwritten")
    script = ROOT / "environment" / "discover.wl"
    command = [str(KERNEL), "-noinit", "-noprompt", "-script", str(script)]
    if args.run:
        command = [str(KERNEL.parents[4] / "WolframKernel.exe"), "-noinit", "-noprompt", "-run", "Get[" + json.dumps(script.as_posix()) + "]"]
    started = dt.datetime.now(dt.timezone.utc)
    record = {
        "timestamp": started.isoformat(),
        "kind": "non_destructive_environment_inventory",
        "command": command,
        "script_sha256": hashlib.sha256(script.read_bytes()).hexdigest(),
        "elevated_administrator": False,
        "os_network_isolation_verified": False,
        "agent_trial": False,
    }
    try:
        environment = os.environ.copy()
        environment["WOLFRAMGUARD_DISCOVERY_LABEL"] = args.label
        p = subprocess.run(command, capture_output=True, timeout=45, env=environment,
                           creationflags=subprocess.CREATE_NO_WINDOW)
        record.update(returncode=p.returncode, stdout=p.stdout.decode("utf-8", "replace"),
                      stderr=p.stderr.decode("utf-8", "replace"))
    except subprocess.TimeoutExpired as e:
        record.update(returncode=None, timeout=True,
                      stdout=(e.stdout or b"").decode("utf-8", "replace"),
                      stderr=(e.stderr or b"").decode("utf-8", "replace"))
    runtime = target / (args.label + "-runtime.json")
    fresh_runtime = runtime.exists() and runtime.stat().st_mtime >= started.timestamp()
    record["inventory_completed"] = "WOLFRAMGUARD_DISCOVERY_END" in record["stdout"] or fresh_runtime
    record["runtime_artifact"] = str(runtime) if fresh_runtime else None
    (target / (args.label + ".json")).write_text(json.dumps(record, indent=2), encoding="utf-8")
    print(json.dumps(record, indent=2))

if __name__ == "__main__":
    main()
