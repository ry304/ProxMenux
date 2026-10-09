"""Offline OIDC security tests. Only ephemeral synthetic identities and keys."""
import copy
import hashlib
import base64
import json
from pathlib import Path
import sys
import time
import unittest
from unittest.mock import patch
from urllib.parse import urlsplit, parse_qs

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from flask import Flask
import jwt
from cryptography.hazmat.primitives.asymmetric import rsa
import flask_oidc_routes as oidc

CONFIG = dict(issuer='https://id.example/application/o/test/', origin='https://monitor.example',
              client_id='test-client', client_secret='synthetic-test-secret',
              subject='owner-subject', email='owner@example.test', local_username='local-owner')
LOCAL = dict(enabled=True, configured=True, declined=False, password_hash='test-only', username='local-owner')
META = dict(issuer=CONFIG['issuer'], authorization_endpoint='https://id.example/authorize',
            token_endpoint='https://id.example/token', jwks_uri='https://id.example/keys',
            code_challenge_methods_supported=['S256'], token_endpoint_auth_methods_supported=['client_secret_basic'])


class OIDCTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        cls.jwk = json.loads(jwt.algorithms.RSAAlgorithm.to_jwk(cls.key.public_key()))
        cls.jwk.update(kid='test-key', use='sig', alg='RS256')

    def setUp(self):
        self.app = Flask(__name__)
        self.app.register_blueprint(oidc.make_blueprint(CONFIG.copy()))
        self.client = self.app.test_client()
        self.local = patch.object(oidc.auth_manager, 'load_auth_config', return_value=LOCAL.copy())
        self.local.start(); self.addCleanup(self.local.stop)
        self.issue = patch.object(oidc.auth_manager, 'generate_token', return_value='synthetic-local-session')
        self.issue_mock = self.issue.start(); self.addCleanup(self.issue.stop)
        self.fetch = patch.object(oidc, 'json_request', side_effect=self.network)
        self.fetch.start(); self.addCleanup(self.fetch.stop)
        self.changes = {}
        self.token_calls = 0

    def network(self, method, url, **kwargs):
        if url.endswith('openid-configuration'): return copy.deepcopy(META)
        if url == META['jwks_uri']: return {'keys': [self.jwk]}
        if url == META['token_endpoint']:
            self.token_calls += 1
            self.assertEqual(kwargs['auth'], (CONFIG['client_id'], CONFIG['client_secret']))
            verifier = kwargs['data']['code_verifier']
            challenge = base64.urlsafe_b64encode(hashlib.sha256(verifier.encode()).digest()).rstrip(b'=').decode()
            self.assertEqual(challenge, self.query['code_challenge'][0])
            self.assertEqual(kwargs['data']['redirect_uri'], CONFIG['origin'] + oidc.CALLBACK)
            return {'id_token': self.encode(self.claims())}
        raise AssertionError('Unexpected network request')

    def claims(self):
        now = int(time.time())
        result = dict(iss=CONFIG['issuer'], aud=CONFIG['client_id'], sub=CONFIG['subject'],
                      email=CONFIG['email'], email_verified=True, nonce=self.query['nonce'][0], iat=now, exp=now+300)
        result.update(self.changes)
        return result

    def encode(self, claims, key=None):
        return jwt.encode(claims, key or self.key, algorithm='RS256', headers={'kid':'test-key'})

    def start(self):
        response = self.client.get('/api/auth/oidc/start', base_url=CONFIG['origin'])
        self.assertEqual(response.status_code,302)
        self.query = parse_qs(urlsplit(response.location).query)
        self.assertEqual(self.query['code_challenge_method'], ['S256'])
        self.assertNotIn('client_secret', self.query)
        for attribute in ['Secure', 'HttpOnly', 'SameSite=Lax', 'Path=/']:
            self.assertIn(attribute, response.headers['Set-Cookie'])
        return response

    def callback(self, query=None, client=None):
        return (client or self.client).get(oidc.CALLBACK, base_url=CONFIG['origin'],
            query_string=query or {'state':self.query['state'][0], 'code':'synthetic-code'})

    def test_success_single_use_handoff_and_bounded_session(self):
        self.start(); response=self.callback()
        self.assertEqual(response.status_code,302)
        self.assertEqual(response.location,CONFIG['origin']+'/')
        self.assertNotIn('synthetic-local-session',response.location)
        expires=self.issue_mock.call_args.kwargs['expires_at']
        self.assertLessEqual(expires,int(time.time())+300)
        response=self.client.post('/api/auth/oidc/complete',base_url=CONFIG['origin'],headers={'Origin':CONFIG['origin']})
        self.assertEqual(response.json['token'],'synthetic-local-session')
        self.assertEqual(self.client.post('/api/auth/oidc/complete',base_url=CONFIG['origin'],headers={'Origin':CONFIG['origin']}).status_code,401)

    def test_state_mismatch_consumes_transaction(self):
        self.start()
        self.assertEqual(self.callback({'state':'wrong','code':'test'}).status_code,401)
        self.assertEqual(self.callback().status_code,401)
        self.assertEqual(self.token_calls,0)

    def test_other_browser_and_forged_headers_denied(self):
        self.start(); other=self.app.test_client()
        self.assertEqual(self.callback(client=other).status_code,401)
        self.assertEqual(other.post('/api/auth/oidc/complete',base_url=CONFIG['origin'],headers={'Origin':CONFIG['origin'],'X-Auth-Request-Email':CONFIG['email']}).status_code,401)

    def test_duplicate_state_and_code_rejected(self):
        for field in ['state','code']:
            with self.subTest(field=field):
                self.start(); query={'state':self.query['state'][0],'code':'test'};query[field]=[query[field],query[field]]
                self.assertEqual(self.callback(query).status_code,401)
        self.assertEqual(self.token_calls,0)

    def test_cross_origin_handoff_rejected(self):
        self.start();self.callback()
        self.assertEqual(self.client.post('/api/auth/oidc/complete',base_url=CONFIG['origin'],headers={'Origin':'https://evil.example'}).status_code,403)

    def test_negative_identity_claims(self):
        cases=[{'sub':'other'},{'email':'other@example.test'},{'email_verified':False},
               {'email_verified':'true'},{'nonce':'wrong'},{'iss':'https://evil.example/'},
               {'aud':'other'},{'aud':[CONFIG['client_id'],'other']},{'azp':'other'},
               {'exp':int(time.time())-5},{'iat':int(time.time())+300}]
        for changes in cases:
            with self.subTest(changes=changes):
                self.changes=changes;self.start()
                self.assertEqual(self.callback().status_code,401)
        self.issue_mock.assert_not_called()

    def test_missing_required_claims_and_bad_signature(self):
        self.start()
        for name in ['sub','exp','iat','nonce','email','email_verified']:
            claims=self.claims();del claims[name]
            with self.assertRaises(Exception):oidc.validate_identity(self.encode(claims),{'keys':[self.jwk]},CONFIG,self.query['nonce'][0])
        wrong=rsa.generate_private_key(public_exponent=65537,key_size=2048)
        with self.assertRaises(Exception):oidc.validate_identity(self.encode(self.claims(),wrong),{'keys':[self.jwk]},CONFIG,self.query['nonce'][0])
        with self.assertRaises(Exception):oidc.validate_identity(self.encode(self.claims()),{'keys':[]},CONFIG,self.query['nonce'][0])

    def test_expired_transaction(self):
        self.start()
        with patch.object(oidc.time,'monotonic',return_value=time.monotonic()+301):
            self.assertEqual(self.callback().status_code,401)
        self.assertEqual(self.token_calls,0)

    def test_recovery_account_required(self):
        with patch.object(oidc.auth_manager,'load_auth_config',return_value={'enabled':False}):
            self.assertFalse(self.client.get('/api/auth/oidc/status').json['enabled'])
            self.assertEqual(self.client.get('/api/auth/oidc/start',base_url=CONFIG['origin']).status_code,404)

    def test_discovery_and_endpoint_pinning(self):
        for changes in [{'issuer':'https://evil.example/'},{'jwks_uri':'http://id.example/keys'},
                        {'token_endpoint':'https://evil.example/token'},{'code_challenge_methods_supported':[]}]:
            with patch.object(oidc,'json_request',return_value=dict(META,**changes)):
                with self.assertRaises(ValueError):oidc.metadata(CONFIG)

    def test_callback_log_redaction(self):
        raw='GET /api/auth/oidc/callback?code=private-code&state=private-state HTTP/1.1'
        safe=oidc.redact_callback(raw)
        self.assertNotIn('private-code',safe)
        self.assertNotIn('private-state',safe)
        self.assertIn('/api/auth/oidc/callback?[redacted]',safe)

    def test_algorithm_confusion_rejected(self):
        self.start()
        token=jwt.encode(self.claims(),'synthetic-hmac-key-of-at-least-32-bytes',algorithm='HS256',headers={'kid':'test-key'})
        with self.assertRaises(ValueError):
            oidc.validate_identity(token,{'keys':[self.jwk]},CONFIG,self.query['nonce'][0])

    def test_pending_capacity_and_replay(self):
        pending=oidc.Pending()
        handle=pending.put({'test':True})
        self.assertTrue(pending.take(handle)['test'])
        with self.assertRaises(ValueError):pending.take(handle)
        for _ in range(1024):pending.put({})
        with self.assertRaises(ValueError):pending.put({})

    def test_canonical_origin_required(self):
        self.assertEqual(self.client.get('/api/auth/oidc/start',base_url='https://evil.example').status_code,404)
        self.assertEqual(self.client.get('/api/auth/oidc/start',base_url='http://monitor.example').status_code,404)

    def test_real_local_session_expiry_cap(self):
        # Exercise the real existing session issuer, but replace its private
        # signing-key loader so no installation configuration is touched.
        self.issue.stop()
        with patch.object(oidc.auth_manager,'_get_jwt_secret',return_value='synthetic-signing-key-at-least-32-bytes'):
            expiry=int(time.time())+60
            token=oidc.auth_manager.generate_token('local-owner',expires_at=expiry)
            claims=jwt.decode(token,'synthetic-signing-key-at-least-32-bytes',
                              algorithms=[oidc.auth_manager.JWT_ALGORITHM],
                              issuer=oidc.auth_manager.JWT_ISSUER,audience=oidc.auth_manager.JWT_AUDIENCE)
            self.assertEqual(claims['exp'],expiry)


if __name__ == '__main__':unittest.main()
