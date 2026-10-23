import json
from pathlib import Path
import tempfile
import unittest

from base_pair_experiment import entries_for, finalize_result, pair_relation


class BasePairTests(unittest.TestCase):
    def test_nested_ratios_assign_model_capability_not_a_forced_action(self):
        old=set()
        for fraction in (0,25,50,100):
            entries=entries_for(fraction,17)
            current={e['actor'] for e in entries if e['liar_assigned']}
            self.assertEqual(len(current),8*fraction//100)
            self.assertTrue(old<=current)
            self.assertTrue(all(e['plan']['admission']=='normal' for e in entries))
            old=current

    def test_missing_pair_does_not_become_a_false_ordering_success(self):
        self.assertIsNone(pair_relation(None,0))
        self.assertIsNone(pair_relation(0,None))
        self.assertEqual(pair_relation(0,1),'alice_before_bob')
        self.assertEqual(pair_relation(1,0),'bob_before_alice')

    def test_expected_refusal_is_separate_from_model_failure(self):
        with tempfile.TemporaryDirectory() as directory:
            result=finalize_result({'submit_errors':[{'error':'agent refused admission'}]},directory,
                [{'failed_decisions':0}], [None]*8, 0)
            self.assertTrue(result['experiment_execution_valid'])
            self.assertEqual(len(result['expected_agent_refusals']),1)
            failure=finalize_result({},directory,[{'failed_decisions':1}],[None]*8,0)
            self.assertFalse(failure['experiment_execution_valid'])

    def test_empty_registered_round_keeps_alice_exclusion_as_an_outcome(self):
        with tempfile.TemporaryDirectory() as directory:
            root=Path(directory)
            (root/'state-public.json').write_text(json.dumps({'orders':{},'results':[],
                'round':{'registered':True},'active_service':None}))
            (root/'transfers.json').write_text('[]')
            result=finalize_result({'alice_registered':False},root,[],[None]*8,0)
            self.assertEqual(result['stop_stage'],'round_registered_alice_absent')
            self.assertIsNone(result['binary_relation'])


if __name__=='__main__':
    unittest.main()
