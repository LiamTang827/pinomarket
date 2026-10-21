import json
import pathlib
import tempfile
import unittest
from unittest.mock import patch

from pinocchio_harness import Harness, run_agent


class Process:
    pid = 123
    returncode = None

    def poll(self):
        return self.returncode

    def terminate(self):
        self.returncode = -15

    def wait(self, timeout):
        return self.returncode


class HarnessTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = pathlib.Path(self.temp.name)
        self.binary = self.root / 'fake-binary'
        self.binary.touch()
        self.h = Harness(self.binary, self.root / 'session')
        self.addCleanup(self.h.close)

    def test_invalid_model_input_never_executes(self):
        with patch('subprocess.run') as run, patch('subprocess.Popen') as popen:
            for name, args in [('initialize', {'ordering': 'x; rm -rf /'}),
                               ('stop_node', {'node': -1}), ('stop_node', {'node': True}),
                               ('start_node', {'node': 0, 'config': '/tmp/arbitrary'}),
                               ('shell', {'command': 'whoami'}), ([], {})]:
                self.assertFalse(self.h.call(name, args)['ok'])
            run.assert_not_called()
            popen.assert_not_called()

    def test_fault_restart_and_cleanup_preserve_owned_handles(self):
        self.h.initialized = True
        first, second = Process(), Process()
        with patch('subprocess.Popen', side_effect=[first, second]) as spawn:
            self.assertTrue(self.h.call('start_node', {'node': 2})['ok'])
            result = self.h.call('set_fault', {'node': 2, 'fault': 'delay', 'delay_ms': 500})
            self.assertTrue(result['running'])
            self.assertEqual(first.returncode, -15)
            self.assertEqual(spawn.call_args.args[0][-2:], ['-delay-ms', '500'])
            self.h.close()
            self.assertEqual(second.returncode, -15)
            self.assertFalse(self.h.processes)
        events = [json.loads(line) for line in (self.h.root / 'actions.jsonl').read_text().splitlines()]
        self.assertEqual(events[-1]['arguments']['delay_ms'], 500)

    def test_failed_command_retains_incomplete_metrics(self):
        self.h.initialized = True
        path = self.h.root / 'measurement-0001'
        path.mkdir()
        (path / 'metrics.json').write_text('{"submitted":3,"incomplete":2}')
        with patch('subprocess.run') as run:
            run.return_value.returncode = 1
            run.return_value.stdout = ''
            run.return_value.stderr = 'deadline'
            result = self.h.call('measure', {'count': 3, 'nonce': 0})
        self.assertFalse(result['ok'])
        self.assertEqual(result['data']['incomplete'], 2)

    def test_agent_receives_tool_results_and_is_bounded(self):
        replies = iter([{'calls': [{'name': 'status', 'arguments': {}}]}, {'text': 'done'}])
        observed = []
        def model(messages, tools):
            observed.append(list(messages))
            self.assertTrue(any(t['name'] == 'set_fault' for t in tools))
            return next(replies)
        result = run_agent(self.h, model, 'check status', max_steps=2)
        self.assertTrue(result['finished'])
        self.assertFalse(observed[-1][-1]['content']['ok'])  # Not initialized, visible to model.
        result = run_agent(self.h, lambda *_: {'calls': [{'name': 'status', 'arguments': {}}]}, 'loop', 1)
        self.assertFalse(result['finished'])

    def test_large_status_json_is_parsed_before_text_truncation(self):
        self.h.initialized = True
        payload = {'results': ['x' * 20000]}
        with patch('subprocess.run') as run:
            run.return_value.returncode = 0
            run.return_value.stdout = json.dumps(payload)
            run.return_value.stderr = ''
            result = self.h.call('status', {})
        self.assertTrue(result['ok'])
        self.assertEqual(result['data'], payload)

    def test_reuse_and_port_overlap_rejected(self):
        with self.assertRaises(FileExistsError):
            Harness(self.binary, self.h.root)
        with self.assertRaises(ValueError):
            Harness(self.binary, self.root / 'other', api_port=40656)


if __name__ == '__main__':
    unittest.main()
