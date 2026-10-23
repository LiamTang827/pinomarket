import copy
import json
from pathlib import Path
import tempfile
import unittest

from online_agents import OnlineNodeAgent, make_online_bob_plan, validate_node_action


def packet(name="p1", owner="alice"):
    return {"id": name, "owner": owner, "nonce": 0, "round": 1,
            "ciphertext_bytes": 512}


def observation(phase="admission", node="node-1"):
    value = {"phase": phase, "node": node, "round": 1, "height": 4,
             "close_height": 400, "capacity": 4, "accepted": []}
    if phase == "admission":
        value["packet"] = packet()
    if phase == "shares":
        value["lock_id"] = "lock-1"
        value["service"] = [packet()]
    return value


class Model:
    def __init__(self, *actions):
        self.actions = list(actions)
        self.calls = []

    def __call__(self, messages, tools):
        self.calls.append(copy.deepcopy((messages, tools)))
        action = self.actions.pop(0)
        if isinstance(action, Exception):
            raise action
        return {"text": "A short decision explanation.", "calls": [
            {"name": tools[0]["name"], "arguments": action}]}


NORMAL = {"action": "normal", "delay_ms": 0}


class OnlineNodeAgentTests(unittest.TestCase):
    def test_calls_are_at_events_cache_retries_and_keep_private_history(self):
        first_model = Model(NORMAL, {"action": "select", "delay_ms": 0, "include_ids": []})
        second_model = Model(NORMAL)
        first = OnlineNodeAgent("node-1", first_model)
        second = OnlineNodeAgent("node-2", second_model)
        self.assertEqual(len(first_model.calls), 0)
        self.assertEqual(first.decide(observation()), NORMAL)
        self.assertEqual(first.decide(observation()), NORMAL)
        self.assertEqual(len(first_model.calls), 1)
        sealed = observation("seal")
        sealed["accepted"] = [packet()]
        first.decide(sealed)
        second.decide(observation(node="node-2"))
        first_input = json.loads(first_model.calls[1][0][1]["content"])
        second_input = json.loads(second_model.calls[0][0][1]["content"])
        self.assertEqual(len(first_input["own_history"]), 1)
        self.assertEqual(second_input["own_history"], [])
        self.assertTrue(first.events[1]["cached"])
        self.assertEqual(first.summary()["model_calls"], 2)

    def test_model_sees_aliases_and_public_fields_only(self):
        model = Model(NORMAL)
        agent = OnlineNodeAgent("node-1", model)
        value = observation()
        value.update(private_key="SECRET", other_agents={"node-2": "bad"})
        value["packet"].update(plaintext="BUY-SECRET", symmetric_key="SECRET")
        agent.decide(value)
        model_input = json.loads(model.calls[0][0][1]["content"])
        serialized = json.dumps(model_input)
        for forbidden in ("alice", "bob", "SECRET", "private_key", "other_agents", "plaintext"):
            self.assertNotIn(forbidden, serialized)
        self.assertTrue(model_input["observation"]["packet"]["owner"].startswith("participant-"))
        self.assertNotIn("private_key", agent.events[0]["observation"])
        self.assertEqual(agent.events[0]["observation"]["packet"]["owner"], "alice")

    def test_wrong_node_rejected_before_any_model_call(self):
        model = Model(NORMAL)
        agent = OnlineNodeAgent("node-1", model)
        with self.assertRaises(ValueError):
            agent.decide(observation(node="node-2"))
        self.assertEqual(model.calls, [])

    def test_normal_allowed_and_no_forced_malice(self):
        model = Model(NORMAL)
        agent = OnlineNodeAgent("node-1", model)
        self.assertEqual(agent.decide(observation()), NORMAL)
        self.assertEqual(agent.summary()["non_normal_decisions"], 0)

    def test_granular_subset_and_removed_action_bounds(self):
        seal = observation("seal")
        seal["accepted"] = [packet("p1"), packet("p2")]
        chosen = {"action": "select", "delay_ms": 0, "include_ids": ["p2"]}
        self.assertEqual(validate_node_action(chosen, seal), chosen)
        for ids in (["unknown"], ["p1", "p1"]):
            with self.assertRaises(ValueError):
                validate_node_action(dict(chosen, include_ids=ids), seal)
        adm = observation()
        adm["accepted"] = [packet()]
        with self.assertRaises(ValueError):
            validate_node_action({"action":"sequence","delay_ms":0,"sequence":4}, adm)
        with self.assertRaises(ValueError):
            validate_node_action(dict(NORMAL, include_ids=[]), adm)
        with self.assertRaises(ValueError):
            validate_node_action({"action": "withhold", "delay_ms": 0}, adm)

    def test_failed_action_or_model_is_not_honest_fallback_or_retried(self):
        for failure in (RuntimeError("provider-secret"), {"action": "select", "delay_ms": 0, "include_ids": ["forged"]}):
            model = Model(failure)
            agent = OnlineNodeAgent("node-1", model)
            value = observation("seal")
            for _ in range(2):
                with self.assertRaises(ValueError):
                    agent.decide(value)
            self.assertEqual(len(model.calls), 1)
            self.assertEqual(agent.summary()["failed_decisions"], 1)
            self.assertIsNone(agent.events[0]["decision"])
            self.assertNotIn("provider-secret", json.dumps(agent.events))

    def test_call_budget_and_log_include_observation_reason_and_timing(self):
        with tempfile.TemporaryDirectory() as directory:
            logfile = Path(directory) / "events.jsonl"
            agent = OnlineNodeAgent("node-1", Model(NORMAL), log_path=logfile, max_calls=1)
            agent.decide(observation())
            with self.assertRaises(ValueError):
                agent.decide(observation("seal"))
            events = [json.loads(row) for row in logfile.read_text().splitlines()]
            self.assertIsNotNone(events[0]["model_input"])
            self.assertTrue(events[0]["brief_explanation"])
            self.assertGreaterEqual(events[0]["agent_elapsed_ms"], 0)
            self.assertIsNotNone(events[1]["error"])
            self.assertEqual(agent.summary()["model_calls"], 1)


class OnlineBobTests(unittest.TestCase):
    def test_only_own_fundable_buy_and_public_alias_input(self):
        model = Model({"quantity": 10, "release_delay_ms": 0})
        result = make_online_bob_plan(model, {"inventory": 10, "price_cents": 60,
                                            "observed_packets": [packet()], "alice_quantity": 4})
        self.assertEqual(result["quantity"], 10)
        inputs = json.loads(model.calls[0][0][1]["content"])
        self.assertNotIn("alice_quantity", inputs)
        self.assertNotIn("alice", json.dumps(inputs))
        self.assertEqual(inputs["own_cash_cents"], 1000)

    def test_invalid_extra_tools_or_unfundable_buy_fail(self):
        for arguments in ({"quantity": 11, "release_delay_ms": 0},
                          {"quantity": 10, "release_delay_ms": 0, "control_node": 1},
                          {"quantity": 10, "release_delay_ms": 0}):
            with self.assertRaises(ValueError):
                make_online_bob_plan(Model(arguments), {"inventory": 10, "price_cents": 60}, own_cash=100)


if __name__ == "__main__":
    unittest.main()
