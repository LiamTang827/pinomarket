import io
import contextlib
import html
import re
import urllib.parse
import json
import os
from pathlib import Path
import tempfile
import time
import unittest
from unittest.mock import patch

try:
    import jwt
    import cryptography
except ImportError:
    raise unittest.SkipTest('Install harness/requirements-chatgpt.txt to test direct ChatGPT login')
from cryptography.hazmat.primitives.asymmetric import rsa

from chatgpt_model import (ChatGPTModel, ConnectionError, ISSUER, RESOURCE, REQUIRED_SCOPES,
                          access_token, atomic_json, parse_callback, profile_id, finish_login, login, TOKEN, JWKS,
                          sse_response, token_record, validate_identity)


def event(kind, **fields):
    return ('data: ' + json.dumps(dict(type=kind, **fields)) + '\n\n').encode()


class IdentityTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        cls.jwk = jwt.algorithms.RSAAlgorithm.to_jwk(cls.key.public_key(), as_dict=True)
        cls.jwk['kid'] = 'test-key'

    def encoded(self, **overrides):
        claims = dict(iss=ISSUER, aud='issued-client', sub='test-user',
                      exp=int(time.time()) + 600, iat=int(time.time()), nonce='pending-nonce')
        claims.update(overrides)
        return jwt.encode(claims, self.key, algorithm='RS256', headers={'kid': 'test-key'})

    def test_valid_identity_and_all_validation_boundaries(self):
        with patch('chatgpt_model.get_json', return_value={'keys': [self.jwk]}):
            self.assertEqual(validate_identity(self.encoded(), 'issued-client', 'pending-nonce')['sub'], 'test-user')
            for token, client, nonce, subject in [
                (self.encoded(), 'other-client', 'pending-nonce', None),
                (self.encoded(), 'issued-client', 'wrong', None),
                (self.encoded(), 'issued-client', 'pending-nonce', 'other-user'),
                (self.encoded(iss='https://untrusted.example'), 'issued-client', 'pending-nonce', None),
                (self.encoded(exp=int(time.time()) - 20), 'issued-client', 'pending-nonce', None),
            ]:
                with self.subTest(client=client, nonce=nonce, subject=subject):
                    with self.assertRaises(ConnectionError):
                        validate_identity(token, client, nonce, subject)
            forged = jwt.encode({'sub': 'test-user'}, 'fake-secret' * 4, algorithm='HS256', headers={'kid': 'test-key'})
            with self.assertRaises(ConnectionError):
                validate_identity(forged, 'issued-client')
            with patch('chatgpt_model.get_json', return_value={'keys': []}):
                with self.assertRaises(ConnectionError):
                    validate_identity(self.encoded(), 'issued-client')

    def test_small_clock_skew_allowed_but_future_tokens_still_rejected(self):
        now = int(time.time())
        with patch('chatgpt_model.get_json', return_value={'keys': [self.jwk]}):
            self.assertEqual(validate_identity(self.encoded(iat=now+3, nbf=now+3),
                                              'issued-client', 'pending-nonce')['sub'], 'test-user')
            for field in ['iat', 'nbf']:
                with self.subTest(field=field):
                    with self.assertRaisesRegex(ConnectionError, 'ImmatureSignatureError'):
                        validate_identity(self.encoded(**{field: now+30}), 'issued-client', 'pending-nonce')

    def test_saved_connection_reused_without_opening_login_or_server(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            account = profile_id('issued-client', 'test-user')
            atomic_json(root/'active.json', {'profile': account})
            atomic_json(root/'accounts'/(account+'.json'), dict(client_id='issued-client', subject='test-user',
                        access_token='SAVED', scopes=list(REQUIRED_SCOPES), expires_at=time.time()+3600))
            with patch('chatgpt_model.HTTPServer') as server, patch('chatgpt_model.webbrowser.open') as browser, contextlib.redirect_stdout(io.StringIO()):
                self.assertEqual(login(root), account)
            server.assert_not_called()
            browser.assert_not_called()

    def test_completed_login_persists_verified_account(self):
        with tempfile.TemporaryDirectory() as directory:
            tokens = dict(id_token=self.encoded(), token_type='Bearer', access_token='ACCESS',
                          refresh_token='REFRESH', scope=' '.join(REQUIRED_SCOPES), expires_in=3600)
            def endpoint(url, **kwargs):
                if url == TOKEN:
                    self.assertEqual(kwargs['form']['client_id'], 'issued-client')
                    self.assertEqual(kwargs['form']['redirect_uri'], 'http://127.0.0.1:12345/auth/callback')
                    return tokens
                self.assertEqual(url, JWKS)
                return {'keys': [self.jwk]}
            with patch('chatgpt_model.get_json', side_effect=endpoint):
                account = finish_login(directory, 'issued-client', 'CODE', 'VERIFIER',
                                       'http://127.0.0.1:12345/auth/callback', 'pending-nonce', 'urn:uuid:test')
            root = Path(directory)
            self.assertEqual(json.loads((root/'active.json').read_text())['profile'], account)
            self.assertFalse((root/'pending-registration.json').exists())
            record = json.loads((root/'accounts'/(account+'.json')).read_text())
            self.assertEqual(record['subject'], 'test-user')
            self.assertEqual(record['refresh_token'], 'REFRESH')

    def test_failed_login_never_overwrites_active_account(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            atomic_json(root/'active.json', {'profile': 'previous-account'})
            tokens = dict(id_token=self.encoded(nonce='wrong-nonce'), token_type='Bearer', access_token='ACCESS',
                          scope=' '.join(REQUIRED_SCOPES), expires_in=3600)
            with patch('chatgpt_model.get_json', side_effect=[tokens, {'keys': [self.jwk]}]):
                with self.assertRaisesRegex(ConnectionError, 'nonce mismatch'):
                    finish_login(root, 'issued-client', 'CODE', 'VERIFIER',
                                 'http://127.0.0.1:12345/auth/callback', 'pending-nonce', 'urn:uuid:test')
            self.assertEqual(json.loads((root/'active.json').read_text()), {'profile': 'previous-account'})
            self.assertEqual(json.loads((root/'pending-registration.json').read_text()), {'client_id': 'issued-client'})
            self.assertEqual(list((root/'accounts').glob('*.json')), [])

    def test_login_page_waits_for_user_and_only_reports_verified_result(self):
        for failed in [False, True]:
            with self.subTest(failed=failed), tempfile.TemporaryDirectory() as directory:
                pages, responses = [], []
                class Server:
                    server_port = 12345
                    def __init__(self, address, handler):
                        self.handler, self.step, self.query = handler, 0, None
                    def __enter__(self):
                        return self
                    def __exit__(self, *_):
                        pass
                    def handle_request(self):
                        obj = object.__new__(self.handler)
                        obj.send_page = lambda title, content, status=200: pages.append((title, content, status))
                        obj.send_response = lambda status: responses.append(status)
                        obj.send_header = lambda *args: None
                        obj.end_headers = lambda: None
                        if self.step == 0:
                            obj.path = '/'
                        elif self.step == 1:
                            link = html.unescape(re.search(r'href="([^"]+)"', pages[0][1])[1])
                            state = urllib.parse.parse_qs(urllib.parse.urlsplit(link).query)['state'][0]
                            obj.path = '/auth/callback?' + urllib.parse.urlencode({'state': state, 'code': 'CODE', 'client_id': 'issued-client'})
                        else:
                            obj.path = '/auth/result'
                        self.step += 1
                        self.handler.do_GET(obj)
                with patch('chatgpt_model.HTTPServer', Server), patch('chatgpt_model.webbrowser.open') as browser, patch('chatgpt_model.finish_login', side_effect=ConnectionError('test failure') if failed else None, return_value='verified-account') as finish, contextlib.redirect_stdout(io.StringIO()):
                    if failed:
                        with self.assertRaisesRegex(ConnectionError, 'test failure'):
                            login(directory, no_browser=True)
                    else:
                        self.assertEqual(login(directory, no_browser=True), 'verified-account')
                browser.assert_not_called()
                finish.assert_called_once()
                self.assertEqual(responses, [303])
                self.assertNotIn('<script', pages[0][1])
                self.assertEqual(pages[-1][0], '尚未连接' if failed else '已连接并保存')

    def test_callback_state_duplicate_and_client_boundaries(self):
        self.assertEqual(parse_callback('state=s&code=c&client_id=issued-client', 's', 'dynamic_agent_client'), ('c', 'issued-client'))
        self.assertEqual(parse_callback('state=s&code=c', 's', 'issued-client'), ('c', 'issued-client'))
        for query, client in [
            ('state=other&code=c&client_id=issued-client', 'dynamic_agent_client'),
            ('state=s&code=c&code=d&client_id=issued-client', 'dynamic_agent_client'),
            ('state=s&code=c', 'dynamic_agent_client'),
            ('state=s&code=c&client_id=other', 'issued-client'),
            ('state=s&error=access_denied', 'issued-client'),
        ]:
            with self.subTest(query=query):
                with self.assertRaises(ConnectionError):
                    parse_callback(query, 's', client)

    def test_missing_plan_permission_cannot_create_usable_record(self):
        tokens = dict(scope='openid profile', token_type='Bearer', access_token='secret', expires_in=3600)
        with self.assertRaises(ConnectionError):
            token_record(tokens, 'issued-client', 'urn:uuid:test', {'sub': 'test-user'})

    def test_refresh_replaces_tokens_atomically_and_reuses_registration(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            account = profile_id('issued-client', 'test-user')
            path = root / 'accounts' / (account + '.json')
            atomic_json(path, dict(client_id='issued-client', subject='test-user',
                        ext_agent_host_id='urn:uuid:test', scopes=list(REQUIRED_SCOPES),
                        expires_at=0, access_token='old-access', refresh_token='old-refresh'))
            atomic_json(root / 'active.json', {'profile': account})
            result = dict(scope=' '.join(REQUIRED_SCOPES), token_type='Bearer',
                          access_token='new-access', refresh_token='new-refresh', expires_in=3600)
            with patch('chatgpt_model.get_json', return_value=result) as request:
                self.assertEqual(access_token(root), 'new-access')
                self.assertEqual(access_token(root), 'new-access')
            request.assert_called_once()
            self.assertEqual(request.call_args.kwargs['form']['client_id'], 'issued-client')
            saved = json.loads(path.read_text())
            self.assertEqual(saved['refresh_token'], 'new-refresh')
            self.assertEqual(os.stat(path).st_mode & 0o777, 0o600)
            self.assertEqual(os.stat(path.parent).st_mode & 0o777, 0o700)


class StreamAndAdapterTests(unittest.TestCase):
    def test_terminal_completion_required_even_after_output(self):
        partial = event('response.output_text.delta', delta='{"calls":[]}')
        for suffix in [b'', event('response.failed', response={'error': {'code': 'subscription_sharing_usage_limit_exceeded'}}), event('response.incomplete')]:
            with self.subTest(suffix=suffix):
                with self.assertRaises(ConnectionError):
                    sse_response(io.BytesIO(partial + suffix))
        text, usage, model = sse_response(io.BytesIO(partial + event('response.completed', response={'usage': {'output_tokens': 5}, 'model': 'test-model'})))
        self.assertEqual(json.loads(text), {'calls': []})
        self.assertEqual(usage['output_tokens'], 5)

    def test_adapter_budget_request_shape_and_private_telemetry(self):
        tools = [{'name': 'status', 'description': 'Read status', 'parameters': {'type': 'object', 'properties': {}}}]
        output = json.dumps({'text': 'ready', 'calls': [{'name': 'status', 'arguments': {}}]})
        response = event('response.output_text.delta', delta=output) + event('response.completed', response={'usage': {'output_tokens': 20}, 'model': 'test-model'})
        with tempfile.TemporaryDirectory() as directory:
            log = Path(directory) / 'calls.jsonl'
            with patch('chatgpt_model.models', return_value=[{'slug': 'test-model'}]), patch('chatgpt_model.access_token', return_value='PRIVATE-TOKEN'), patch('chatgpt_model.open_http', return_value=io.BytesIO(response)) as request:
                adapter = ChatGPTModel(directory, 'test-model', max_calls=1, telemetry=log)
                result = adapter([{'role': 'user', 'content': 'PRIVATE-OBSERVATION'}], tools)
                self.assertEqual(result['calls'][0]['name'], 'status')
                payload = request.call_args.kwargs['payload']
                self.assertFalse(payload['store'])
                self.assertTrue(payload['stream'])
                self.assertEqual(request.call_args.args[0], RESOURCE + '/responses')
                self.assertNotIn('temperature', payload)
                with self.assertRaises(ConnectionError):
                    adapter([], tools)
            telemetry = log.read_text()
            self.assertNotIn('PRIVATE-TOKEN', telemetry)
            self.assertNotIn('PRIVATE-OBSERVATION', telemetry)
            self.assertEqual(json.loads(telemetry)['status'], 'completed')

    def test_unknown_tool_cannot_be_returned_to_harness(self):
        output = json.dumps({'text': '', 'calls': [{'name': 'shell', 'arguments': {'command': 'anything'}}]})
        response = event('response.output_text.delta', delta=output) + event('response.completed', response={})
        with patch('chatgpt_model.models', return_value=[{'slug': 'test-model'}]), patch('chatgpt_model.access_token', return_value='PRIVATE-TOKEN'), patch('chatgpt_model.open_http', return_value=io.BytesIO(response)):
            adapter = ChatGPTModel('/tmp/unused-test-state', 'test-model')
            with self.assertRaises(ConnectionError):
                adapter([], [{'name': 'status'}])


if __name__ == '__main__':
    unittest.main()
