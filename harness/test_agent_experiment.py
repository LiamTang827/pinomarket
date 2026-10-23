import argparse
import csv
import json
import pathlib
import re
import tempfile
import threading
import unittest
from unittest.mock import patch

from agent_experiment import FRACTIONS, N, plan_suite, summarize
from role_agents import honest_plan


class ExperimentPlanningTests(unittest.TestCase):
    def test_gpt_plans_once_per_actor_and_reuses_policy_in_nested_fractions(self):
        calls = []
        lock = threading.Lock()

        def model(messages, tools):
            self.assertEqual(len(messages), 1)
            name = tools[0]["name"]
            task = messages[0]["content"]
            with lock:
                calls.append((name, task))
            if name == "configure_policy":
                # This test's provider chooses a permitted list omission.
                return {"calls": [{"name": name, "arguments": dict(honest_plan(), seal="omit")}]}
            scenario = re.search(r"Use scenario '([^']+)'", task).group(1)
            return {"calls": [{"name": name, "arguments": {
                "attack": scenario, "orders": 2, "quantity": 4, "spacing_ms": 0}}]}

        with patch("agent_experiment.subprocess.run", side_effect=AssertionError("no process in planning")):
            suite = plan_suite(20261023, model)
        self.assertEqual(suite["backend"], "chatgpt-policy")
        self.assertEqual(len(calls), 12)  # Eight private node prompts + four Bob scenarios.
        node_calls = [task for name, task in calls if name == "configure_policy"]
        self.assertEqual(len(node_calls), N)
        self.assertEqual(len({re.search(r"You are (node-\d+)", task).group(1) for task in node_calls}), N)
        previous = set()
        policies = {}
        for fraction in FRACTIONS:
            entries = suite["nodes"][str(fraction)]
            assigned = {entry["actor"] for entry in entries if entry["liar_assigned"]}
            self.assertEqual(len(assigned), N * fraction // 100)
            self.assertTrue(previous <= assigned)
            previous = assigned
            for entry in entries:
                if entry["liar_assigned"]:
                    actor = entry["actor"]
                    self.assertEqual(entry["plan"], policies.setdefault(actor, entry["plan"]))
                else:
                    self.assertEqual(entry["plan"], honest_plan())

    def test_scripted_plans_are_repeatable_without_model(self):
        with patch("agent_experiment.subprocess.run", side_effect=AssertionError("no process in planning")):
            first = plan_suite(14)
            second = plan_suite(14)
        self.assertEqual(first, second)
        self.assertEqual(first["backend"], "scripted-reference")
        for fraction in FRACTIONS:
            self.assertEqual(len(first["nodes"][str(fraction)]), 8)


class ExperimentReportingTests(unittest.TestCase):
    def test_error_rows_retained_and_scripted_report_does_not_claim_gpt_authorship(self):
        with tempfile.TemporaryDirectory(prefix="pino-report-") as directory:
            root = pathlib.Path(directory)
            binary = root / "fake-binary"
            binary.write_bytes(b"test fixture; never executed")
            args = argparse.Namespace(binary=str(binary), backend="scripted", model="unused",
                                      seed=14, lead_ms=100, deadline=25, window_blocks=12)
            records = [
                {"fraction": 25, "profile": "mixed", "scenario": "none", "alice_filled": 4,
                 "alice_observed": {"processed_observed_ms": 100}, "audit_verified": True},
                {"fraction": 25, "profile": "mixed", "scenario": "race", "alice_filled": 2,
                 "alice_observed": {"processed_observed_ms": 140}, "audit_verified": True},
                {"fraction": 100, "profile": "mixed", "scenario": "flood", "error": "fixed deadline reached"},
            ]
            with patch("agent_experiment.subprocess.run", side_effect=AssertionError("reporting must not execute")):
                summarize(root, records, plan_suite(14), args)
            summary = json.loads((root / "summary.json").read_text())
            self.assertEqual(len(summary["runs"]), 3)
            self.assertEqual(summary["backend"], "scripted-reference")
            self.assertIsNone(summary["model"])
            self.assertEqual(summary["runs"][-1]["error"], "fixed deadline reached")
            self.assertEqual(summary["runs"][1]["alice_fill_loss_vs_control"], 2)
            self.assertEqual(summary["runs"][1]["extra_processing_ms_vs_control"], 40)
            with (root / "summary.csv").open(newline="") as stream:
                rows = list(csv.DictReader(stream))
            self.assertEqual(len(rows), 3)
            self.assertEqual(rows[-1]["scenario"], "flood")
            self.assertEqual(rows[-1]["error"], "fixed deadline reached")
            report = (root / "REPORT.zh-CN.md").read_text()
            self.assertNotIn("GPT 在计时前为每个", report)
            self.assertIn("scripted-reference", report)


if __name__ == "__main__":
    unittest.main()
