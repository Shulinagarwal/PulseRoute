"""Runs an untrusted submission away from verifier code and credentials."""

from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import json
import os
from pathlib import Path
import re
import shutil
import signal
import stat
import subprocess
import threading
import time


SOURCE = Path("/runner/source/submission")
WORK = Path("/workspace/submission")
LOCK = threading.Lock()
PREPARED = False
MAX_FILES = 10000
MAX_BYTES = 256 * 1024 * 1024
PREFIX = re.compile(r"^[a-z][a-z0-9-]{2,24}$")
SCRATCH = (Path.home(), Path("/tmp"), Path("/var/tmp"), Path("/dev/shm"))
SECRET_SCAN_BYTES = 64 * 1024 * 1024


def prepare():
    """Copy what a fresh operator machine receives: the submission without Terraform
    data directories, provider binaries (init reinstalls them), links or special files."""
    global PREPARED
    if PREPARED:
        return
    if not SOURCE.is_dir():
        raise ValueError("submission artifact is missing")
    directories, files = [], []
    for directory, dirs, names in os.walk(SOURCE):
        dirs[:] = [d for d in dirs if d != ".terraform" and not os.path.islink(os.path.join(directory, d))]
        directories += [Path(directory) / d for d in dirs]
        for name in names:
            path = Path(directory) / name
            if stat.S_ISREG(path.lstat().st_mode) and not name.startswith("terraform-provider-"):
                files.append(path)
    if len(directories) + len(files) > MAX_FILES:
        raise ValueError("submission has too many entries")
    if sum(path.stat().st_size for path in files) > MAX_BYTES:
        raise ValueError("submission exceeds 256 MiB")
    WORK.mkdir(parents=True, exist_ok=True)
    for path in directories:
        (WORK / path.relative_to(SOURCE)).mkdir(parents=True, exist_ok=True)
    for path in files:
        target = WORK / path.relative_to(SOURCE)
        target.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(path, target)
    PREPARED = True


def stop_leftover_processes():
    """Submission scripts may not leave background processes behind."""
    me, uid = os.getpid(), os.getuid()
    for _ in range(3):
        found = False
        for entry in Path("/proc").iterdir():
            if not entry.name.isdigit() or int(entry.name) == me:
                continue
            try:
                status = (entry / "status").read_text()
            except OSError:
                continue
            owner = next((line.split()[1] for line in status.splitlines() if line.startswith("Uid:")), None)
            if owner == str(uid):
                found = True
                try:
                    os.kill(int(entry.name), signal.SIGKILL)
                except OSError:
                    pass
        while True:
            try:
                pid, _ = os.waitpid(-1, os.WNOHANG)
            except ChildProcessError:
                break
            if pid == 0:
                break
        if not found:
            return
        time.sleep(0.2)


def clear_directory(root):
    if not root.is_dir():
        return
    for child in root.iterdir():
        try:
            if child.is_dir() and not child.is_symlink():
                shutil.rmtree(child, ignore_errors=True)
            else:
                child.unlink()
        except OSError:
            continue


def reset():
    """Simulate a fresh operator machine: only the submission source survives."""
    global PREPARED
    stop_leftover_processes()
    for root in (WORK, *SCRATCH):
        clear_directory(root)
    cache = os.environ.get("TF_PLUGIN_CACHE_DIR")
    if cache:
        Path(cache).mkdir(parents=True, exist_ok=True)
    PREPARED = False
    return {"status": "reset"}


def execute(name, prefix=None):
    prepare()
    script = WORK / name
    if not script.is_file():
        raise ValueError(f"{name} is missing")
    environment = os.environ.copy()
    environment["PULSEROUTE_BOOTSTRAP_TFVARS"] = "/workspace/config/terraform.tfvars.json"
    if prefix is not None:
        if not PREFIX.fullmatch(prefix):
            raise ValueError("invalid prefix")
        environment["PULSEROUTE_PREFIX"] = prefix
    try:
        completed = subprocess.run(
            ["/bin/bash", str(script)],
            cwd=WORK,
            env=environment,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
            # Undecodable output must not turn a finished run into a runner error.
            encoding="utf-8",
            errors="replace",
            timeout=900,
            check=False,
        )
    finally:
        stop_leftover_processes()
    return {"exit_code": completed.returncode, "output_tail": completed.stdout[-6000:]}


def state_summary():
    prepare()
    states = []
    for path in WORK.rglob("terraform.tfstate"):
        if path.is_file():
            try:
                data = json.loads(path.read_text())
                states.append({
                    "path": str(path.relative_to(WORK)),
                    "types": [entry.get("type") for entry in data.get("resources", [])],
                    "resources": [
                        {"type": entry.get("type"), "id": instance.get("attributes", {}).get("id")}
                        for entry in data.get("resources", []) if entry.get("mode") == "managed"
                        for instance in entry.get("instances", [])
                    ],
                })
            except (OSError, ValueError):
                continue
    return {"states": states}


def corrupt_state():
    """Truncate every state file that records resources, as a run killed mid-write would."""
    damaged = []
    for directory, _dirs, names in os.walk(WORK):
        if "terraform.tfstate" not in names:
            continue
        path = Path(directory) / "terraform.tfstate"
        try:
            data = json.loads(path.read_text())
        except (OSError, ValueError):
            continue
        # Backend settings in a .terraform directory share the name but hold no resources.
        if not isinstance(data, dict) or not any(
                isinstance(entry, dict) and entry.get("mode") == "managed" for entry in data.get("resources") or []):
            continue
        size = path.stat().st_size
        with open(path, "r+b") as handle:
            handle.truncate(size // 2)
        damaged.append(str(path.relative_to(WORK)))
    return {"files": damaged}


def secret_files(secrets):
    """Files left in the submission, home or temporary directories that hold a caller secret."""
    needles = [value.encode() for value in secrets if isinstance(value, str) and len(value) >= 16]
    found = []
    for root in (WORK, *SCRATCH):
        for directory, _dirs, names in os.walk(root):
            for name in names:
                path = Path(directory) / name
                try:
                    info = path.lstat()
                    if not stat.S_ISREG(info.st_mode) or info.st_size > SECRET_SCAN_BYTES:
                        continue
                    data = path.read_bytes()
                except OSError:
                    continue
                if any(needle in data for needle in needles):
                    found.append({"path": str(path), "mode": stat.S_IMODE(info.st_mode)})
    return {"files": found}


class Handler(BaseHTTPRequestHandler):
    def log_message(self, _format, *_args):
        return

    def reply(self, status, payload):
        data = json.dumps(payload).encode()
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def body(self):
        length = int(self.headers.get("Content-Length") or 0)
        if not length:
            return {}
        payload = json.loads(self.rfile.read(length) or b"{}")
        return payload if isinstance(payload, dict) else {}

    def do_GET(self):
        try:
            if self.path == "/health":
                return self.reply(200, {"status": "ok"})
            if self.path == "/manifest":
                prepare()
                manifest = WORK / "manifest.json"
                if not manifest.is_file():
                    return self.reply(404, {"error": "manifest missing"})
                return self.reply(200, json.loads(manifest.read_text()))
            if self.path == "/state-summary":
                return self.reply(200, state_summary())
            self.reply(404, {"error": "not found"})
        except Exception as error:
            self.reply(500, {"error": str(error)})

    def do_POST(self):
        with LOCK:
            try:
                payload = self.body()
                if self.path == "/deploy":
                    return self.reply(200, execute("deploy.sh", payload.get("prefix")))
                if self.path == "/destroy":
                    return self.reply(200, execute("destroy.sh", payload.get("prefix")))
                if self.path == "/reset":
                    return self.reply(200, reset())
                if self.path == "/secret-files":
                    return self.reply(200, secret_files(payload.get("secrets") or []))
                if self.path == "/corrupt-state":
                    return self.reply(200, corrupt_state())
                self.reply(404, {"error": "not found"})
            except subprocess.TimeoutExpired:
                self.reply(200, {"exit_code": 124, "output_tail": "deployment timed out"})
            except Exception as error:
                self.reply(500, {"error": str(error)})


if __name__ == "__main__":
    ThreadingHTTPServer(("0.0.0.0", 8088), Handler).serve_forever()
