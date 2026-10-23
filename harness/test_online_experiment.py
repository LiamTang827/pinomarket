import json
from pathlib import Path
import tempfile
import unittest
from unittest import mock

from online_experiment import LatencyHonestAgent, logical_key


def observation():
    return {'phase':'admission', 'node':'node-1', 'round':1, 'height':3,
            'close_height':103, 'capacity':4, 'accepted':[],
            'packet':{'id':'old-id', 'owner':'alice', 'nonce':0, 'round':1,
                      'ciphertext_bytes':100}}


class WaitControlTests(unittest.TestCase):
    def test_queue_wait_is_not_counted_twice(self):
        obs = observation()
        trace = [{'observation':obs, 'agent_elapsed_ms':100,
                  'decision':{'action':'refuse','delay_ms':0}, 'cached':False}]
        with tempfile.TemporaryDirectory() as directory:
            agent = LatencyHonestAgent('node-1', trace, Path(directory)/'events.jsonl')
            with mock.patch('online_experiment.time.monotonic_ns', side_effect=[0,40_000_000,100_000_000]), mock.patch('online_experiment.time.sleep') as sleep:
                action = agent.decide(obs)
            sleep.assert_called_once_with(.06)
            self.assertEqual(action, {'action':'normal','delay_ms':0})
            self.assertEqual(agent.events[0]['agent_elapsed_ms'], 100)

    def test_new_ciphertext_ids_match_same_trader_nonce(self):
        left = observation()
        right = json.loads(json.dumps(left))
        right['packet']['id'] = 'fresh-encryption'
        self.assertEqual(logical_key(left), logical_key(right))

    def test_failed_model_decision_is_not_a_successful_wait_trace(self):
        obs = observation()
        with tempfile.TemporaryDirectory() as directory:
            agent = LatencyHonestAgent('node-1', [{'observation':obs, 'agent_elapsed_ms':50000,
                'decision':None, 'error':{'category':'model_or_action_failure'}}], Path(directory)/'events.jsonl')
            with mock.patch('online_experiment.time.sleep') as sleep:
                agent.decide(obs)
            sleep.assert_called_once_with(0)
            self.assertFalse(agent.events[0]['matched'])


if __name__=='__main__':
    unittest.main()
