"""Opt-in real-browser test with disposable TLS mock IdP and compiled login UI.

Set PROXMENUX_TEST_BROWSER to an existing Chromium executable. Requires Node
with built-in WebSocket, the existing Python test dependencies, and npm build.
No downloads, live identities, production config, or system trust changes.
"""
import base64
import datetime
import hashlib
import ipaddress
import json
import os
from pathlib import Path
import secrets
import shutil
import subprocess
import sys
import tempfile
import threading
import time
import unittest
from unittest.mock import patch
from urllib.parse import urlencode

from flask import Flask, jsonify, redirect, request, send_from_directory
from werkzeug.serving import make_server, WSGIRequestHandler
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID
import jwt
import requests

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import flask_oidc_routes as oidc


class QuietHandler(WSGIRequestHandler):
    def log_request(self, *args, **kwargs): pass
    def log_error(self, *args, **kwargs): pass


@unittest.skipUnless(os.environ.get('PROXMENUX_TEST_BROWSER'), 'Opt-in disposable browser test')
class BrowserOIDCTest(unittest.TestCase):
    def test_compiled_login_with_tls_mock_idp(self):
        appimage = Path(__file__).resolve().parents[2]
        self.assertTrue((appimage/'out/index.html').is_file(), 'Run npm build first')
        self.assertTrue(shutil.which('node'), 'Existing Node is required')
        with tempfile.TemporaryDirectory(prefix='proxmenux-oidc-browser-') as temporary:
            root = Path(temporary)
            key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
            name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, 'Disposable OIDC Test')])
            now = datetime.datetime.now(datetime.timezone.utc)
            cert = (x509.CertificateBuilder().subject_name(name).issuer_name(name)
                    .public_key(key.public_key()).serial_number(x509.random_serial_number())
                    .not_valid_before(now-datetime.timedelta(minutes=1)).not_valid_after(now+datetime.timedelta(hours=1))
                    .add_extension(x509.BasicConstraints(ca=True,path_length=None),critical=True)
                    .add_extension(x509.SubjectAlternativeName([x509.DNSName('localhost'),x509.IPAddress(ipaddress.ip_address('127.0.0.1'))]),critical=False)
                    .sign(key,hashes.SHA256()))
            certfile,keyfile=root/'cert.pem',root/'key.pem'
            certfile.write_bytes(cert.public_bytes(serialization.Encoding.PEM))
            keyfile.write_bytes(key.private_bytes(serialization.Encoding.PEM,serialization.PrivateFormat.PKCS8,serialization.NoEncryption()))
            spki=base64.b64encode(hashlib.sha256(key.public_key().public_bytes(serialization.Encoding.DER,serialization.PublicFormat.SubjectPublicKeyInfo)).digest()).decode()
            jwk=json.loads(jwt.algorithms.RSAAlgorithm.to_jwk(key.public_key()));jwk.update(kid='mock-key',alg='RS256',use='sig')
            codes={};scenario={'mode':'owner'}
            idp=Flask('mock-idp')
            server_idp=make_server('127.0.0.1',0,idp,threaded=True,ssl_context=(str(certfile),str(keyfile)),request_handler=QuietHandler)
            issuer=f'https://localhost:{server_idp.server_port}/issuer/'
            config=dict(issuer=issuer,origin='https://127.0.0.1:8008',client_id='mock-client',client_secret=secrets.token_urlsafe(32),subject='mock-owner',email='owner@example.test',local_username='mock-local')
            @idp.get('/issuer/.well-known/openid-configuration')
            def discovery():
                return jsonify(issuer=issuer,authorization_endpoint=issuer+'authorize',token_endpoint=issuer+'token',jwks_uri=issuer+'keys',code_challenge_methods_supported=['S256'],token_endpoint_auth_methods_supported=['client_secret_basic'])
            @idp.get('/issuer/authorize')
            def authorize():
                if request.args.get('redirect_uri')!=config['origin']+oidc.CALLBACK or request.args.get('code_challenge_method')!='S256':return '',400
                code=secrets.token_urlsafe(32);codes[code]=dict(request.args)
                return redirect(config['origin']+oidc.CALLBACK+'?'+urlencode({'code':code,'state':request.args['state']}))
            @idp.post('/issuer/token')
            def token():
                if not request.authorization or request.authorization.username!=config['client_id'] or request.authorization.password!=config['client_secret']:return '',401
                args=codes.pop(request.form.get('code'),None)
                challenge=base64.urlsafe_b64encode(hashlib.sha256(request.form.get('code_verifier','').encode()).digest()).rstrip(b'=').decode()
                if not args or challenge!=args['code_challenge'] or request.form.get('redirect_uri')!=args['redirect_uri']:return '',400
                claims=dict(iss=issuer,aud=config['client_id'],sub='mock-owner' if scenario['mode']=='owner' else 'other-subject',email=config['email'],email_verified=True,nonce=args['nonce'],iat=int(time.time()),exp=int(time.time())+300)
                return jsonify(id_token=jwt.encode(claims,key,algorithm='RS256',headers={'kid':'mock-key'}),access_token='synthetic-unused',token_type='Bearer')
            @idp.get('/issuer/keys')
            def keys():return jsonify(keys=[jwk])
            rp=Flask('mock-monitor',static_folder=None);rp.register_blueprint(oidc.make_blueprint(config))
            @rp.get('/api/auth/status')
            def auth_status():
                supplied=request.headers.get('Authorization','').removeprefix('Bearer ')
                return jsonify(auth_enabled=True,auth_configured=True,authenticated=bool(oidc.auth_manager.verify_token(supplied)))
            @rp.get('/api/protected-test')
            def protected():return ('',200) if oidc.auth_manager.verify_token(request.headers.get('Authorization','').removeprefix('Bearer ')) else ('',401)
            @rp.post('/test/scenario')
            def set_scenario():
                scenario['mode']=request.json['mode'];return '',204
            @rp.get('/')
            def index():return send_from_directory(appimage/'out','index.html')
            @rp.get('/<path:path>')
            def files(path):
                if path.startswith('api/'):return jsonify({})
                return send_from_directory(appimage/'out',path)
            server_rp=make_server('127.0.0.1',8008,rp,threaded=True,ssl_context=(str(certfile),str(keyfile)),request_handler=QuietHandler)
            original_send=requests.sessions.Session.send
            def verified_send(session,req,**kwargs):
                if not req.url.startswith(issuer):raise AssertionError('Unexpected outbound request')
                kwargs['verify']=str(certfile)
                return original_send(session,req,**kwargs)
            local=dict(enabled=True,configured=True,declined=False,password_hash='synthetic',username='mock-local',revoked_tokens=[])
            process=None
            try:
                with patch.object(oidc.auth_manager,'load_auth_config',return_value=local),patch.object(oidc.auth_manager,'_get_jwt_secret',return_value=secrets.token_urlsafe(48)),patch.object(oidc.auth_manager,'AUTH_CONFIG_FILE',root/'absent-auth.json'),patch.object(requests.sessions.Session,'send',verified_send):
                    for server in [server_idp,server_rp]:threading.Thread(target=server.serve_forever,daemon=True).start()
                    profile=root/'profile'
                    process=subprocess.Popen([os.environ['PROXMENUX_TEST_BROWSER'],'--headless=new','--no-first-run','--disable-extensions','--disable-background-networking','--no-proxy-server',f'--user-data-dir={profile}','--remote-debugging-port=0','--remote-debugging-address=127.0.0.1',f'--ignore-certificate-errors-spki-list={spki}','about:blank'],stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL,creationflags=subprocess.CREATE_NO_WINDOW if os.name=='nt' else 0)
                    result=subprocess.run(['node',str(Path(__file__).with_name('browser_oidc.mjs')),str(profile),config['origin']],capture_output=True,text=True,timeout=60)
                    self.assertEqual(result.returncode,0, result.stderr[-1000:])
                    report=json.loads(result.stdout.strip());self.assertTrue(report['desktopOwnerLogin']);self.assertTrue(report['mobileWrongOwnerDenied'])
                    print('BROWSER_RESULT='+json.dumps(report))
            finally:
                if process:
                    process.terminate();process.wait(timeout=10)
                for server in [server_idp,server_rp]:server.shutdown();server.server_close()


if __name__=='__main__':unittest.main()
