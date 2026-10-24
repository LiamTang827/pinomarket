import copy
import io
from unittest.mock import patch, MagicMock
import unittest

from performance_experiment import (PROTOCOL_ROUTES, OBSERVER_ROUTES, http_delta,
                                    interval_cost, observe_stages, p2p_delta,
                                    parse_cpu_time, request)


def net(sent=10, received=999, start='2026-10-25T00:00:00Z', duration=100):
    return {'result': {'peers': [{'node_info': {'id': 'remote-1'},
        'connection_status': {'Duration': str(duration),
            'SendMonitor': {'Bytes': str(sent), 'Start': start},
            'RecvMonitor': {'Bytes': str(received), 'Start': start}}}]}}


def telemetry():
    return {'schema': 1, 'node': 'node-1', 'process_started_at': '2026-10-25T00:00:00Z',
        'http': {r: {'requests': 0, 'request_body_bytes': 0, 'response_body_bytes': 0,
                     'handler_ms_total': 0., 'failures': 0, 'status_codes': {}}
                 for r in PROTOCOL_ROUTES + OBSERVER_ROUTES}}


class PerformanceAccountingTests(unittest.TestCase):
    def test_p2p_counts_sent_once_and_rejects_reset_even_if_bytes_grew(self):
        self.assertEqual(p2p_delta(net(), net(sent=30,received=999999,duration=200)),20)
        with self.assertRaisesRegex(ValueError,'restarted'):
            p2p_delta(net(),net(sent=100,start='another-connection',duration=200))
        with self.assertRaisesRegex(ValueError,'decreased'):
            p2p_delta(net(),net(sent=1,duration=200))
        with self.assertRaisesRegex(ValueError,'peer set changed'):
            p2p_delta(net(),{'result':{'peers':[]}})

    def test_protocol_and_observer_bodies_are_disjoint(self):
        old=telemetry()
        new=copy.deepcopy(old)
        new['http']['/submit'].update(requests=1,request_body_bytes=100,response_body_bytes=50,
            handler_ms_total=2., status_codes={'200':1})
        new['http']['/state'].update(requests=1,response_body_bytes=9000,
            handler_ms_total=3.,status_codes={'200':1})
        before={'nodes':{'node-1':{'telemetry':old,'net_info':net()}}}
        after={'nodes':{'node-1':{'telemetry':new,'net_info':net(sent=30,duration=200)}}}
        result=interval_cost(before,after)
        self.assertEqual(result['p2p_mconnection_sent_bytes'],20)
        self.assertEqual(result['protocol_http_body_bytes'],150)
        self.assertEqual(result['observer_http_body_bytes'],9000)
        self.assertEqual(result['measured_layered_protocol_bytes'],170)
        self.assertEqual(result['http_routes']['/submit']['requests'],1)

    def test_http_restart_missing_or_negative_counters_invalidate_measurement(self):
        old=telemetry()
        new=copy.deepcopy(old)
        new['process_started_at']='restarted'
        with self.assertRaisesRegex(ValueError,'restart'):
            http_delta(old,new)
        new=copy.deepcopy(old)
        old['http']['/gossip']['requests']=2
        with self.assertRaisesRegex(ValueError,'decreased'):
            http_delta(old,new)
        old=telemetry()
        del new['http']['/submit']['response_body_bytes']
        with self.assertRaises(KeyError):
            http_delta(old,new)

    def test_missing_order_does_not_borrow_old_business_result(self):
        order={'id':'new-encrypted-packet','ref':'alice:0','submission_started_at_ms':100}
        stale={'monotonic_s':2.,'state':{'orders':{'old-packet':{}},
            'results':[{'order':'alice:0','filled':1}]}}
        self.assertNotIn('result',observe_stages([order],[stale],1.,3)[0])
        state={'orders':{'new-encrypted-packet':{}},'services':[
            {'items':['new-encrypted-packet'],'shares':{'new-encrypted-packet':[1,2,3]}}],
            'results':[{'order':'alice:0','filled':1}]}
        row=observe_stages([order],[{'monotonic_s':2.,'state':state}],1.,3)[0]
        self.assertEqual(row['processed_observed_at_ms'],1000.)
        self.assertEqual(row['shares_ready_observed_at_ms'],1000.)

    def test_local_requests_bypass_system_proxy_and_reject_remote_urls(self):
        opener = MagicMock()
        opener.open.return_value = io.StringIO('{"ok": true}')
        with patch('performance_experiment.urllib.request.build_opener', return_value=opener) as factory, patch('performance_experiment.urllib.request.urlopen', side_effect=AssertionError('default proxy path used')):
            self.assertEqual(request('http://127.0.0.1:31001/metrics'), {'ok': True})
            self.assertEqual(factory.call_args[0][0].proxies, {})
            opener.open.assert_called_once_with('http://127.0.0.1:31001/metrics', timeout=3)
        for url in ('https://127.0.0.1:1234/metrics', 'http://example.com:1234/metrics',
                    'http://user@127.0.0.1:1234/metrics', 'http://127.0.0.1:1234/metrics?query=1'):
            with self.assertRaises(ValueError):
                request(url)

    def test_local_request_failure_names_the_endpoint(self):
        opener = MagicMock()
        opener.open.side_effect = ConnectionError('closed')
        with patch('performance_experiment.urllib.request.build_opener', return_value=opener):
            with self.assertRaisesRegex(RuntimeError, 'http://127.0.0.1:31001/net_info'):
                request('http://127.0.0.1:31001/net_info')

    def test_ps_clock_formats(self):
        self.assertAlmostEqual(parse_cpu_time('0:01.25'),1.25)
        self.assertEqual(parse_cpu_time('02:03:04'),7384)
        self.assertEqual(parse_cpu_time('1-02:03:04'),93784)


if __name__=='__main__':
    unittest.main()
