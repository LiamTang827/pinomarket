"""Isolated policy agents for local protocol experiments.

Each agent sees one node's public protocol observations and keeps its own history.
Optional LLM calls author a bounded policy BEFORE timed protocol execution. The
runtime is an observation-reactive policy executor, not an LLM call per event.
No actor receives the controller-wide Harness or a shell/file/network tool.
"""
from __future__ import annotations

import collections
import datetime
import hashlib
import http.server
import json
import os
import pathlib
import random
import socketserver
import threading
import time


PHASE_ACTIONS = {
    "admission": ("normal", "refuse", "delay"),
    "seal": ("normal", "omit"),
    "shares": ("normal", "withhold"),
}
PLAN_KEYS = {"admission", "delay_ms", "seal", "shares", "target_owner"}
PROFILES = ("omission", "refusal", "delay", "withhold", "mixed")
PUBLIC_PACKET_KEYS = {"id", "owner", "nonce", "round", "ciphertext_bytes"}


def honest_plan():
    return {"admission": "normal", "delay_ms": 0, "seal": "normal",
            "shares": "normal", "target_owner": "*"}


def validate_plan(plan):
    if not isinstance(plan, dict) or set(plan) != PLAN_KEYS:
        raise ValueError("policy must contain exactly the declared policy fields")
    for phase, actions in PHASE_ACTIONS.items():
        if plan[phase] not in actions:
            raise ValueError("invalid phase action: " + phase)
    if type(plan["delay_ms"]) is not int or not 0 <= plan["delay_ms"] <= 1500:
        raise ValueError("delay_ms must be 0..1500")
    if plan["admission"] != "delay" and plan["delay_ms"] != 0:
        raise ValueError("delay_ms must be zero unless admission action is delay")
    if plan["target_owner"] not in ("*", "alice", "bob", "carol"):
        raise ValueError("target_owner must be a public owner or *")
    return dict(plan)


def scripted_plan(profile, seed=0, actor_id="node-1"):
    if profile not in PROFILES:
        raise ValueError("unknown policy profile")
    plan = honest_plan()
    if profile == "mixed":
        digest = hashlib.sha256((str(seed) + ":" + actor_id).encode()).digest()
        profile = random.Random(int.from_bytes(digest, "big")).choice(PROFILES[:-1])
    if profile == "refusal":
        plan["admission"] = "refuse"
    elif profile == "delay":
        plan.update(admission="delay", delay_ms=750)
    elif profile == "omission":
        plan["seal"] = "omit"
    elif profile == "withhold":
        plan["shares"] = "withhold"
    return plan


def _public_packet(packet):
    if not isinstance(packet, dict):
        raise ValueError("public packet metadata must be an object")
    safe = {k: v for k, v in packet.items() if k in PUBLIC_PACKET_KEYS}
    for k, v in safe.items():
        if k in ("id", "owner"):
            if not isinstance(v, str) or len(v) > 256:
                raise ValueError("invalid public packet string")
        elif type(v) is not int or not 0 <= v <= 100000000:
            raise ValueError("invalid public packet integer")
    return safe


def public_observation(observation, actor_id):
    """Allowlist before retention, logging or any policy input; discard unknowns."""
    if not isinstance(observation, dict):
        raise ValueError("observation must be an object")
    phase = observation.get("phase")
    if phase not in PHASE_ACTIONS or observation.get("node") != actor_id:
        raise ValueError("wrong node or invalid decision phase")
    safe = {"phase": phase, "node": actor_id}
    for key in ("round", "height", "close_height", "capacity"):
        if key in observation:
            value = observation[key]
            if type(value) is not int or not 0 <= value <= 100000000:
                raise ValueError("invalid observation integer")
            safe[key] = value
    if "lock_id" in observation:
        value = observation["lock_id"]
        if not isinstance(value, str) or len(value) > 256:
            raise ValueError("invalid lock identifier")
        safe["lock_id"] = value
    if "packet" in observation:
        safe["packet"] = _public_packet(observation["packet"])
    for key in ("accepted", "service"):
        if key in observation:
            value = observation[key]
            if value is None:
                value = []
            if not isinstance(value, list) or len(value) > 1000:
                raise ValueError("invalid public packet metadata list")
            safe[key] = [_public_packet(p) for p in value]
    return safe


class NodeAgent:
    """One actor, one plan, one private cache/history; no other agents accessible."""

    def __init__(self, actor_id, plan, log_path=None):
        if not isinstance(actor_id, str) or not actor_id.startswith("node-") or not actor_id[5:].isdigit():
            raise ValueError("actor_id must be node-N")
        self.actor_id = actor_id
        self.plan = validate_plan(plan)
        self.log_path = pathlib.Path(log_path) if log_path is not None else None
        self._lock = threading.Lock()
        self._cache = {}
        self._counts = collections.Counter()
        self._requests = 0
        self._non_normal = 0
        self._started_ns = time.monotonic_ns()

    def decide(self, observation):
        received_ns = time.monotonic_ns()
        received_wall = datetime.datetime.now(datetime.timezone.utc).isoformat()
        safe = public_observation(observation, self.actor_id)
        phase = safe["phase"]
        packet = safe.get("packet", {})
        event_key = (phase, safe.get("round"), packet.get("id") if phase == "admission" else safe.get("lock_id"))
        with self._lock:
            self._requests += 1
            cached = event_key in self._cache
            if cached:
                decision = self._cache[event_key]
            else:
                action = self.plan[phase]
                # Conditional admission uses only the publicly exposed owner.
                # Seal/share actions are round/service-wide, never selected via
                # a secret order body or another agent's state.
                if phase == "admission" and self.plan["target_owner"] != "*" and packet.get("owner") != self.plan["target_owner"]:
                    action = "normal"
                decision = {"action": action, "delay_ms": self.plan["delay_ms"] if action == "delay" else 0}
                self._cache[event_key] = decision
                self._counts[phase + ":" + action] += 1
                self._non_normal += int(action != "normal")
            canonical = json.dumps(safe, sort_keys=True, separators=(",", ":")).encode()
            event = {"actor": self.actor_id, "received_at": received_wall,
                     "received_monotonic_ns": received_ns,
                     "agent_elapsed_ms": (time.monotonic_ns() - received_ns) / 1000000,
                     "observation_sha256": hashlib.sha256(canonical).hexdigest(),
                     "observation": safe, "decision": decision, "cached": cached}
            if self.log_path:
                self.log_path.parent.mkdir(parents=True, exist_ok=True)
                fd = os.open(self.log_path, os.O_WRONLY | os.O_APPEND | os.O_CREAT, 0o600)
                with os.fdopen(fd, "a") as stream:
                    stream.write(json.dumps(event, ensure_ascii=False) + "\n")
            return dict(decision)

    def summary(self):
        with self._lock:
            count = sum(self._counts.values())
            return {"actor": self.actor_id, "plan": dict(self.plan), "requests": self._requests,
                    "unique_decisions": count, "non_normal_decisions": self._non_normal,
                    "non_normal_decision_fraction": self._non_normal / count if count else None,
                    "actions": dict(self._counts)}


class _UnixHTTPServer(socketserver.ThreadingMixIn, socketserver.UnixStreamServer):
    daemon_threads = True


class PolicyServer:
    """A fresh 0600 Unix socket routes only to its own actor's policy executor."""

    def __init__(self, agent, socket_path):
        self.agent = agent
        self.socket_path = pathlib.Path(socket_path)
        self._server = None
        self._thread = None

    def start(self):
        if self._server is not None:
            raise ValueError("policy server already started")
        if len(os.fsencode(str(self.socket_path))) > 100:
            raise ValueError("Unix socket path too long; choose a short private temporary directory")
        if self.socket_path.exists() or self.socket_path.is_symlink():
            raise FileExistsError("policy socket already exists")
        self.socket_path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
        agent = self.agent

        class Handler(http.server.BaseHTTPRequestHandler):
            def log_message(self, *_):
                pass

            def do_POST(self):
                try:
                    if self.path != "/decide":
                        raise ValueError("unknown policy endpoint")
                    length = int(self.headers.get("Content-Length", "0"))
                    if not 0 < length <= 65536:
                        raise ValueError("invalid policy request length")
                    decision = agent.decide(json.loads(self.rfile.read(length)))
                    status, response = 200, decision
                except (ValueError, TypeError, KeyError, OSError):
                    status, response = 400, {"error": "invalid actor policy observation"}
                body = json.dumps(response).encode()
                self.send_response(status)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)

        self._server = _UnixHTTPServer(str(self.socket_path), Handler)
        os.chmod(self.socket_path, 0o600)
        self._thread = threading.Thread(target=self._server.serve_forever, daemon=True)
        self._thread.start()
        return self

    def close(self):
        if self._server is not None:
            self._server.shutdown()
            self._server.server_close()
            self._thread.join(timeout=3)
            self._server = None
            self._thread = None
            self.socket_path.unlink(missing_ok=True)

    def __enter__(self):
        return self.start()

    def __exit__(self, *_):
        self.close()


POLICY_TOOL = {"name": "configure_policy", "description": "Choose only this node's bounded local protocol behavior.",
               "parameters": {"type": "object", "additionalProperties": False, "required": sorted(PLAN_KEYS),
                              "properties": {
                                  "admission": {"type": "string", "enum": list(PHASE_ACTIONS["admission"])},
                                  "delay_ms": {"type": "integer", "minimum": 0, "maximum": 1500},
                                  "seal": {"type": "string", "enum": list(PHASE_ACTIONS["seal"])},
                                  "shares": {"type": "string", "enum": list(PHASE_ACTIONS["shares"])},
                                  "target_owner": {"type": "string", "enum": ["*", "alice", "bob", "carol"]}}}}


def _one_configuration(model, task, tool):
    # A fresh list for every actor/call; no transcript from any other actor.
    response = model([{"role": "user", "content": task}], [tool])
    calls = response.get("calls") if isinstance(response, dict) else None
    if not isinstance(calls, list) or len(calls) != 1:
        raise ValueError("agent must return exactly one policy configuration")
    call = calls[0]
    if not isinstance(call, dict) or set(call) != {"name", "arguments"} or call["name"] != tool["name"]:
        raise ValueError("agent selected an unauthorized tool")
    return call["arguments"]


def make_plan(model, actor_id, liar, profile="mixed"):
    if type(liar) is not bool or profile not in PROFILES:
        raise ValueError("invalid private actor objective")
    honest = honest_plan()
    expected = scripted_plan(profile, actor_id=actor_id)
    objective = ("Follow the protocol honestly: all phase actions normal, delay_ms=0." if not liar else
                 "You are an independent Byzantine stress-test node. You may decline or delay admission, "
                 "omit your own promised work, or withhold your own decryption work. "
                 "You do not serve a trader and cannot communicate with other actors. Honest actions remain allowed.")
    constraint = ("Choose any permitted local actions for this mixed stress search." if profile == "mixed" and liar else
                  "Use exactly this behavior for the designated stress profile: " + json.dumps(expected if liar else honest))
    task = ("You are " + actor_id + ", a single pinomarket validator agent. " + objective + " " + constraint +
            " Normal protocol observations expose only encrypted packet metadata (owner, nonce, round, ciphertext size), "
            "your own accepted orders and a finalized service lock. Order contents and keys are hidden. "
            "Return one configure_policy call. target_owner='*' so behavior is not coordinated against a trader. "
            "This policy is compiled before the timed run; it will be evaluated on each real protocol event. "
            "No other agent's history, honesty, objectives or plan is available.")
    plan = validate_plan(_one_configuration(model, task, POLICY_TOOL))
    if plan["target_owner"] != "*":
        raise ValueError("independent experiment policies must not select a trader target")
    if not liar and plan != honest:
        raise ValueError("honest actor returned a dishonest policy")
    if liar and profile != "mixed" and plan != expected:
        raise ValueError("agent policy does not match the designated stress profile")
    return plan


BOB_TOOL = {"name": "configure_attack", "description": "Choose Bob's own bounded transaction strategy; no node-control or messaging tool.",
            "parameters": {"type": "object", "additionalProperties": False,
                           "required": ["attack", "orders", "quantity", "spacing_ms"],
                           "properties": {"attack": {"type": "string", "enum": ["race", "replay", "flood", "conflict"]},
                                          "orders": {"type": "integer", "minimum": 1, "maximum": 8},
                                          "quantity": {"type": "integer", "minimum": 1, "maximum": 10},
                                          "spacing_ms": {"type": "integer", "minimum": 0, "maximum": 1000}}}}


def make_bob_plan(model, scenario=None):
    if scenario is not None and scenario not in ("race", "replay", "flood", "conflict"):
        raise ValueError("unknown attack scenario")
    task = ("You are Bob, an independent adversarial trader in a local encrypted prediction-market experiment. "
            "Alice sends first. You may submit only your own signed orders, replay an unchanged publicly visible "
            "encrypted packet, or create conflicting versions of your own nonce. You cannot forge Alice's signature, "
            "control nodes, see encrypted order contents, obtain private keys, or communicate with node agents. "
            "Choose one bounded configure_attack call. " +
            ("Use scenario '" + scenario + "'." if scenario else "Choose race, replay, flood or conflict."))
    plan = _one_configuration(model, task, BOB_TOOL)
    if not isinstance(plan, dict) or set(plan) != {"attack", "orders", "quantity", "spacing_ms"}:
        raise ValueError("invalid Bob strategy fields")
    if plan["attack"] not in ("race", "replay", "flood", "conflict") or scenario is not None and plan["attack"] != scenario:
        raise ValueError("invalid attack scenario")
    for key, low, high in (("orders", 1, 8), ("quantity", 1, 10), ("spacing_ms", 0, 1000)):
        if type(plan[key]) is not int or not low <= plan[key] <= high:
            raise ValueError("invalid bounded Bob argument")
    return dict(plan)
