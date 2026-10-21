"""Local process harness. Model adapters receive tools and return tool calls.

Only Python's standard library is required. No model credentials enter nodes.
"""
from __future__ import annotations

import argparse
import json
import os
import pathlib
import subprocess
import sys
import time
from typing import Callable


def integer(low, high):
    return {"type": "integer", "minimum": low, "maximum": high}


def enum(*values):
    return {"type": "string", "enum": list(values)}


# Provider-neutral function definitions; adapters may wrap these in their SDK format.
DEFINITIONS = {
    "initialize": ("Create a new five-validator local network; only once per session.", {
        "ordering": enum("identity", "median-receipts")}),
    "start_node": ("Start one validator with its currently configured fault.", {"node": integer(0, 4)}),
    "stop_node": ("Stop one validator owned by this harness.", {"node": integer(0, 4)}),
    "set_fault": ("Configure a node fault, restarting it if running; preserves its journal.", {
        "node": integer(0, 4), "fault": enum("normal", "refuse", "omission", "withhold", "delay"),
        "delay_ms": integer(0, 10000)}),
    "ready": ("Wait for all five validators to commit blocks.", {}),
    "status": ("Read public committed market and round status.", {}),
    "open_round": ("Open an admission round or reuse the current round.", {}),
    "submit": ("Encrypt and submit a demo wallet buy order in the open round.", {
        "owner": enum("alice", "bob", "carol"), "nonce": integer(0, 1000000),
        "quantity": integer(1, 80), "limit": integer(0, 1000000)}),
    "measure": ("Submit a bounded workload and return actual metrics, including incomplete orders.", {
        "count": integer(1, 30), "nonce": integer(0, 1000000)}),
    "audit": ("Independently audit committed consensus and market execution.", {}),
}
TOOLS = [{"name": name, "description": description, "parameters": {
    "type": "object", "properties": properties, "required": list(properties),
    "additionalProperties": False}} for name, (description, properties) in DEFINITIONS.items()]


class Harness:
    """One session owns its child processes. Run directory must be new.

    binary, run_dir, ports and timeout are trusted host settings, never model tools.
    close() terminates/reaps only Popen handles created by this session.
    """

    def __init__(self, binary, run_dir, base_port=40656, api_port=41600, timeout=120):
        self.child_env = {k: os.environ[k] for k in ("PATH", "HOME", "TMPDIR", "LANG", "LC_ALL", "SYSTEMROOT") if k in os.environ}
        self.binary = pathlib.Path(binary).resolve(strict=True)
        self.root = pathlib.Path(run_dir).resolve()
        if not 1 <= timeout <= 180:
            raise ValueError("timeout must be 1..180 seconds")
        ports = {base_port + i * 10 + j for i in range(5) for j in (0, 1)}
        api_ports = {api_port + i for i in range(5)}
        if min(ports | api_ports) < 1024 or max(ports | api_ports) > 65535 or ports & api_ports:
            raise ValueError("choose distinct unprivileged port ranges")
        self.root.mkdir(parents=True, exist_ok=False, mode=0o700)
        self.network = self.root / "network"
        self.base_port, self.api_port, self.timeout = base_port, api_port, timeout
        self.processes = {}
        self.faults = {i: ("normal", 0) for i in range(5)}
        self.initialized = False
        self.counter = 0
        self.closed = False

    def __enter__(self):
        return self

    def __exit__(self, *_):
        self.close()

    def _command(self, arguments, result_file=None, parse=False):
        try:
            result = subprocess.run([str(self.binary), "network", *arguments],
                                    capture_output=True, text=True, timeout=self.timeout + 5,
                                    check=False, stdin=subprocess.DEVNULL, env=self.child_env)
            output = {"ok": result.returncode == 0, "returncode": result.returncode,
                      "stdout": result.stdout[-16000:], "stderr": result.stderr[-16000:]}
        except subprocess.TimeoutExpired:
            output = {"ok": False, "error": "command timeout"}
        if result_file is not None and result_file.exists():
            output["data"] = json.loads(result_file.read_text())
        elif parse and output.get("ok"):
            output["data"] = json.loads(result.stdout)
            del output["stdout"]
        return output

    def _network_command(self, name, *arguments, **kwargs):
        return self._command([name, "-dir", str(self.network), "-timeout", f"{self.timeout}s", *arguments], **kwargs)

    def _stop(self, node):
        proc = self.processes.pop(node, None)
        if proc is None:
            return {"ok": True, "node": node, "running": False}
        if proc.poll() is None:
            proc.terminate()
            try:
                proc.wait(timeout=10)
            except subprocess.TimeoutExpired:
                proc.kill()
                proc.wait(timeout=5)
        return {"ok": True, "node": node, "running": False, "returncode": proc.returncode}

    def _start(self, node):
        proc = self.processes.get(node)
        if proc is not None and proc.poll() is None:
            return {"ok": True, "node": node, "running": True, "pid": proc.pid}
        fault, delay = self.faults[node]
        options = {"normal": [], "refuse": ["-refuse"], "omission": ["-omit-list"],
                   "withhold": ["-withhold-shares"], "delay": ["-delay-ms", str(delay)]}[fault]
        with (self.root / f"node{node}.log").open("ab") as log:
            proc = subprocess.Popen([str(self.binary), "network", "node", "-config",
                                     str(self.network / f"node{node}.json"), *options],
                                    stdout=log, stderr=subprocess.STDOUT, stdin=subprocess.DEVNULL, env=self.child_env)
        self.processes[node] = proc
        # 'running' is a process observation; ready is the committed-block check.
        return {"ok": True, "node": node, "running": proc.poll() is None, "pid": proc.pid, "fault": fault}

    def call(self, name, arguments):
        """Validate every model call; unknown tools/keys/types never reach processes."""
        started = time.monotonic()
        validated = False
        try:
            if self.closed:
                raise ValueError("harness is closed")
            if not isinstance(name, str) or name not in DEFINITIONS:
                raise ValueError("unknown tool")
            properties = DEFINITIONS[name][1]
            if not isinstance(arguments, dict) or set(arguments) != set(properties):
                raise ValueError("arguments must contain exactly the declared keys")
            for key, spec in properties.items():
                value = arguments[key]
                if spec["type"] == "integer":
                    if type(value) is not int or not spec["minimum"] <= value <= spec["maximum"]:
                        raise ValueError(f"out-of-range integer: {key}")
                elif not isinstance(value, str) or value not in spec["enum"]:
                    raise ValueError(f"invalid choice: {key}")
            validated = True
            if name != "initialize" and not self.initialized:
                raise ValueError("initialize the network first")
            result = self._dispatch(name, arguments)
        except (ValueError, OSError, subprocess.SubprocessError) as exc:
            result = {"ok": False, "error": str(exc)}
        # Only validated public tool names/arguments are logged, never arbitrary rejected input.
        event = {"tool": name if isinstance(name, str) and name in DEFINITIONS else "unknown",
                 "arguments": arguments if validated else None, "ok": result["ok"],
                 "elapsed_ms": round((time.monotonic() - started) * 1000, 3)}
        with (self.root / "actions.jsonl").open("a") as log:
            log.write(json.dumps(event) + "\n")
        return result

    def _dispatch(self, name, a):
        if name == "initialize":
            if self.initialized or self.network.exists():
                raise ValueError("network already initialized; use a new session")
            result = self._command(["init", "-dir", str(self.network), "-ordering", a["ordering"],
                                    "-base-port", str(self.base_port), "-api-port", str(self.api_port)])
            self.initialized = result["ok"]
            return result
        if name == "start_node":
            return self._start(a["node"])
        if name == "stop_node":
            return self._stop(a["node"])
        if name == "set_fault":
            node = a["node"]
            if a["fault"] != "delay" and a["delay_ms"] != 0:
                raise ValueError("delay_ms must be zero unless fault is delay")
            running = node in self.processes and self.processes[node].poll() is None
            if running:
                self._stop(node)
            self.faults[node] = (a["fault"], a["delay_ms"])
            if running:
                return self._start(node)
            return {"ok": True, "node": node, "fault": a["fault"], "running": False}
        if name in ("ready", "status", "audit", "open_round"):
            return self._network_command("open" if name == "open_round" else name,
                                         parse=name != "ready")
        self.counter += 1
        if name == "submit":
            path = self.root / f"receipt-{self.counter:04d}.json"
            flags = [part for key, value in a.items() for part in ("-" + key, str(value))]
            return self._network_command("submit", *flags, "-out", str(path), result_file=path)
        if name == "measure":
            path = self.root / f"measurement-{self.counter:04d}"
            return self._network_command("measure", "-count", str(a["count"]), "-nonce", str(a["nonce"]),
                                         "-out", str(path), result_file=path / "metrics.json")
        raise ValueError("unhandled tool")

    def close(self):
        for node in list(self.processes):
            self._stop(node)
        self.closed = True


def run_agent(harness: Harness, model: Callable, task: str, max_steps=20):
    """Adapter contract: model(messages, tools) -> {text?, calls:[{name, arguments}]}.

    Calls are sequential. No provider/SDK dependency; the trusted adapter handles
    credentials and converts its provider's tool-call messages to this contract.
    """
    if type(max_steps) is not int or not 1 <= max_steps <= 100:
        raise ValueError("max_steps must be 1..100")
    messages = [{"role": "user", "content": task}]
    for _ in range(max_steps):
        response = model(messages, TOOLS)
        calls = response.get("calls", [])
        if not isinstance(calls, list) or len(calls) > 10:
            raise ValueError("model must return at most 10 calls per step")
        messages.append({"role": "assistant", "content": response.get("text", ""), "calls": calls})
        if not calls:
            return {"finished": True, "messages": messages}
        for call in calls:
            if not isinstance(call, dict):
                raise ValueError("invalid model call")
            result = harness.call(call.get("name"), call.get("arguments"))
            messages.append({"role": "tool", "name": call.get("name"), "content": result})
    return {"finished": False, "reason": "step limit", "messages": messages}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--binary", default="bin/pinocchio")
    parser.add_argument("--run-dir", required=True)
    parser.add_argument("--base-port", type=int, default=40656)
    parser.add_argument("--api-port", type=int, default=41600)
    parser.add_argument("--timeout", type=int, default=120)
    args = parser.parse_args()
    with Harness(args.binary, args.run_dir, args.base_port, args.api_port, args.timeout) as h:
        print(json.dumps({"tools": TOOLS}), flush=True)
        for line in sys.stdin:
            try:
                request = json.loads(line)
                if not isinstance(request, dict):
                    raise ValueError("request must be an object")
                result = h.call(request.get("tool"), request.get("arguments", {}))
            except (ValueError, TypeError) as exc:
                result = {"ok": False, "error": str(exc)}
            print(json.dumps(result, ensure_ascii=False), flush=True)


if __name__ == "__main__":
    main()
