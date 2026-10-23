import copy
import http.client
import json
import os
import pathlib
import socket
import stat
import tempfile
import unittest

from role_agents import (NodeAgent, PolicyServer, honest_plan, make_bob_plan, make_plan,
                         public_observation, scripted_plan, validate_plan)


class UnixConnection(http.client.HTTPConnection):
    def __init__(self, path):
        super().__init__("localhost", timeout=2)
        self.path = path

    def connect(self):
        self.sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        self.sock.settimeout(self.timeout)
        self.sock.connect(str(self.path))


def observation(node="node-1", phase="admission", owner="alice", packet_id="cipher-1"):
    return {"phase": phase, "node": node, "round": 1, "height": 8,
            "capacity": 3, "close_height": 20,
            "packet": {"id": packet_id, "owner": owner, "nonce": 0,
                       "round": 1, "ciphertext_bytes": 300}}


class RoleAgentTests(unittest.TestCase):
    def test_plan_validation_rejects_privilege_and_invalid_phase(self):
        for replacement in ({"shell": "id"}, {"admission": "withhold"},
                            {"delay_ms": True}, {"delay_ms": 1501},
                            {"shares": "reverse_sequence"}, {"target_owner": "private-key"}):
            with self.subTest(replacement=replacement), self.assertRaises(ValueError):
                validate_plan(dict(honest_plan(), **replacement))
        self.assertEqual(validate_plan(honest_plan()), honest_plan())

    def test_wrong_actor_rejected_and_unknown_fields_not_retained(self):
        agent = NodeAgent("node-1", honest_plan())
        with self.assertRaises(ValueError):
            agent.decide(observation(node="node-2"))
        raw = observation()
        raw.update(private_key="secret", other_agents=[{"policy": "withhold"}], plaintext="buy")
        raw["packet"].update(key="secret", signed_plaintext="hidden")
        safe = public_observation(raw, "node-1")
        encoded = json.dumps(safe)
        self.assertNotIn("secret", encoded)
        self.assertNotIn("plaintext", encoded)
        self.assertNotIn("other_agents", encoded)

    def test_profiles_only_have_phase_permitted_actions(self):
        expected = {"refusal": ("admission", "refuse"),
                    "delay": ("admission", "delay"), "omission": ("seal", "omit"),
                    "withhold": ("shares", "withhold")}
        for profile, (phase, action) in expected.items():
            with self.subTest(profile=profile):
                plan = validate_plan(scripted_plan(profile))
                agent = NodeAgent("node-1", plan)
                response = agent.decide(observation(phase=phase))
                self.assertEqual(response["action"], action)
                self.assertEqual(response["delay_ms"], 750 if action == "delay" else 0)
        self.assertEqual(scripted_plan("mixed", 3, "node-1"), scripted_plan("mixed", 3, "node-1"))


    def test_agents_and_returned_decisions_do_not_share_mutable_state(self):
        a = NodeAgent("node-1", scripted_plan("omission"))
        b = NodeAgent("node-2", honest_plan())
        result = a.decide(observation(phase="seal"))
        result["action"] = "normal"
        self.assertEqual(a.decide(observation(phase="seal"))["action"], "omit")
        self.assertEqual(b.summary()["requests"], 0)
        self.assertEqual(a.summary()["unique_decisions"], 1)
        self.assertEqual(a.summary()["non_normal_decisions"], 1)

    def test_logs_capture_only_safe_observations_and_both_clocks(self):
        with tempfile.TemporaryDirectory(prefix="pinoagent-") as directory:
            path = pathlib.Path(directory) / "agent.jsonl"
            agent = NodeAgent("node-1", honest_plan(), path)
            raw = observation()
            raw["private_key"] = "never-log-this"
            agent.decide(raw)
            event = json.loads(path.read_text())
            self.assertGreater(event["received_monotonic_ns"], 0)
            self.assertIn("+00:00", event["received_at"])
            self.assertNotIn("never-log-this", path.read_text())
            self.assertEqual(stat.S_IMODE(path.stat().st_mode), 0o600)

    def test_private_socket_routes_only_own_node_and_cleans_up(self):
        # /tmp path keeps macOS sockaddr_un below its 104-byte path limit.
        with tempfile.TemporaryDirectory(prefix="pa-", dir="/tmp") as directory:
            path = pathlib.Path(directory) / "n.sock"
            with PolicyServer(NodeAgent("node-1", honest_plan()), path):
                self.assertEqual(stat.S_IMODE(path.stat().st_mode), 0o600)
                conn = UnixConnection(path)
                conn.request("POST", "/decide", json.dumps(observation()), {"Content-Type": "application/json"})
                response = conn.getresponse()
                self.assertEqual(response.status, 200)
                self.assertEqual(json.loads(response.read()), {"action": "normal", "delay_ms": 0})
                conn.close()
                conn = UnixConnection(path)
                conn.request("POST", "/decide", json.dumps(observation(node="node-8")))
                response = conn.getresponse()
                self.assertEqual(response.status, 400)
                response.read()
                conn.close()
            self.assertFalse(path.exists())

    def test_preexisting_socket_path_is_never_unlinked(self):
        with tempfile.TemporaryDirectory(prefix="pa-", dir="/tmp") as directory:
            path = pathlib.Path(directory) / "n.sock"
            path.write_text("owner data")
            with self.assertRaises(FileExistsError):
                PolicyServer(NodeAgent("node-1", honest_plan()), path).start()
            self.assertEqual(path.read_text(), "owner data")

    def test_gpt_policy_calls_have_fresh_isolated_transcripts(self):
        seen = []
        def model(messages, tools):
            seen.append(copy.deepcopy(messages))
            self.assertEqual([t["name"] for t in tools], ["configure_policy"])
            # A real provider-neutral adapter returns the bounded tool contract.
            return {"calls": [{"name": "configure_policy", "arguments": honest_plan()}]}
        make_plan(model, "node-1", False)
        make_plan(model, "node-2", False)
        self.assertEqual(len(seen[0]), 1)
        self.assertEqual(len(seen[1]), 1)
        self.assertIn("node-1", seen[0][0]["content"])
        self.assertNotIn("node-1", seen[1][0]["content"])
        self.assertNotIn("ratio", seen[1][0]["content"])
        self.assertNotIn("Bob", seen[1][0]["content"])

    def test_honest_llm_cannot_gain_dishonest_action_and_no_fallback(self):
        def model(*_):
            return {"calls": [{"name": "configure_policy", "arguments": scripted_plan("withhold")}]}
        with self.assertRaises(ValueError):
            make_plan(model, "node-1", False)
        def malicious(*_):
            return {"calls": [{"name": "stop_node", "arguments": {"node": 0}}]}
        with self.assertRaises(ValueError):
            make_plan(malicious, "node-1", True)

    def test_mixed_byzantine_llm_may_choose_omission(self):
        def model(*_):
            return {"calls": [{"name": "configure_policy", "arguments": scripted_plan("omission")}]}
        self.assertEqual(make_plan(model, "node-1", True)["seal"], "omit")

    def test_bob_can_only_configure_bounded_own_strategy(self):
        observed_tools = []
        def model(messages, tools):
            observed_tools.extend(t["name"] for t in tools)
            return {"calls": [{"name": "configure_attack", "arguments": {
                "attack": "replay", "orders": 2, "quantity": 4, "spacing_ms": 0}}]}
        self.assertEqual(make_bob_plan(model, "replay")["attack"], "replay")
        self.assertEqual(observed_tools, ["configure_attack"])
        with self.assertRaises(ValueError):
            make_bob_plan(model, "race")


if __name__ == "__main__":
    unittest.main()
