# ProxMenux Monitor — optional owner-only OIDC login
# Copyright (c) 2026 ProxMenux contributors. License: GPL-3.0.
"""Authorization code + S256; credentials and transient state stay on the server.

Disabled unless a private configuration file is explicitly supplied. Local login
and recovery remain required. This module never creates users or changes grants.
"""
import base64
import hashlib
import hmac
import json
import logging
import os
from pathlib import Path
import secrets
import re
import stat
import threading
import time
from urllib.parse import urlencode, urlsplit

import jwt
import requests
from flask import Blueprint, jsonify, redirect, request
import auth_manager

COOKIE = '__Host-proxmenux-oidc'
CALLBACK = '/api/auth/oidc/callback'


def redact_callback(message):
    return re.sub(r'(/api/auth/oidc/callback)\?[^\s"\x1b]*', r'\1?[redacted]', message)


class CallbackLogFilter(logging.Filter):
    def filter(self, record):
        record.msg = redact_callback(record.getMessage())
        record.args = ()
        return True


class CallbackLogWriter:
    def __init__(self, stream):
        self.stream = stream

    def write(self, message):
        return self.stream.write(redact_callback(message))

    def flush(self):
        return self.stream.flush()


class Pending:
    """Bounded, single-use, process-local state; restarts invalidate pending logins."""
    def __init__(self):
        self.items = {}
        self.lock = threading.Lock()

    def put(self, value, ttl=300):
        with self.lock:
            now = time.monotonic()
            self.items = {k: v for k, v in self.items.items() if v[0] > now}
            if len(self.items) >= 1024:
                raise ValueError('Capacity exceeded')
            handle = secrets.token_urlsafe(32)
            self.items[handle] = (now + ttl, value)
            return handle

    def take(self, handle):
        with self.lock:
            expiry, value = self.items.pop(handle, (0, None))
        if expiry <= time.monotonic():
            raise ValueError('Expired transaction')
        return value


def https_url(value):
    u = urlsplit(value)
    if u.scheme != 'https' or not u.hostname or u.username or u.password or u.query or u.fragment:
        raise ValueError('HTTPS URL required')
    return u


def load_settings():
    filename = os.environ.get('PROXMENUX_OIDC_CONFIG')
    if not filename:
        return None
    path = Path(filename)
    info = path.lstat()
    if not stat.S_ISREG(info.st_mode) or info.st_uid != os.geteuid() or info.st_mode & 0o077:
        raise ValueError('Private configuration required')
    config = json.loads(path.read_text())
    validate_settings(config)
    return config


def validate_settings(config):
    issuer = https_url(config['issuer'])
    origin = https_url(config['origin'])
    if origin.path or config['origin'].endswith('/'):
        raise ValueError('Origin must not contain a path')
    if not issuer.path.endswith('/'):
        raise ValueError('Use exact issuer, including trailing slash')
    for key in ['client_id', 'client_secret', 'subject', 'email', 'local_username']:
        if not isinstance(config.get(key), str) or not config[key].strip():
            raise ValueError('Missing required setting')


def json_request(method, url, **kwargs):
    # No redirects (especially for credential-bearing token requests), bounded
    # reads, normal CA verification, and no environment-supplied proxy credentials.
    with requests.Session() as session:
        session.trust_env = False
        with session.request(method, url, timeout=(5, 10), allow_redirects=False,
                             stream=True, **kwargs) as response:
            if response.status_code != 200:
                raise ValueError('Identity provider unavailable')
            data = bytearray()
            for chunk in response.iter_content(8192):
                data.extend(chunk)
                if len(data) > 262144:
                    raise ValueError('Oversized response')
            return json.loads(data)


def metadata(config):
    result = json_request('GET', config['issuer'] + '.well-known/openid-configuration')
    if result.get('issuer') != config['issuer'] or 'S256' not in result.get('code_challenge_methods_supported', []):
        raise ValueError('Invalid discovery metadata')
    if 'client_secret_basic' not in result.get('token_endpoint_auth_methods_supported', []):
        raise ValueError('Unsupported client authentication')
    for key in ['authorization_endpoint', 'token_endpoint', 'jwks_uri']:
        endpoint = https_url(result[key])
        if endpoint.netloc != urlsplit(config['issuer']).netloc:
            raise ValueError('Cross-origin identity endpoint')
    return result


def validate_identity(token, keys, config, nonce):
    if not isinstance(token, str) or len(token) > 32768:
        raise ValueError('Invalid identity token')
    header = jwt.get_unverified_header(token)
    if header.get('alg') != 'RS256' or not isinstance(header.get('kid'), str):
        raise ValueError('Unsupported signing key')
    candidates = [k for k in keys.get('keys', []) if k.get('kid') == header['kid']
                  and k.get('kty') == 'RSA' and k.get('use', 'sig') == 'sig'
                  and k.get('alg', 'RS256') == 'RS256' and 'd' not in k]
    if len(candidates) != 1:
        raise ValueError('Unknown signing key')
    key = jwt.PyJWK.from_dict(candidates[0], algorithm='RS256').key
    if key.key_size < 2048:
        raise ValueError('Weak signing key')
    claims = jwt.decode(token, key, algorithms=['RS256'], issuer=config['issuer'],
                        audience=config['client_id'], leeway=0,
                        options={'require': ['iss', 'aud', 'sub', 'exp', 'iat', 'nonce', 'email', 'email_verified'],
                                 'strict_aud': True})
    if (claims['sub'] != config['subject'] or claims['email'] != config['email']
            or claims['email_verified'] is not True
            or not isinstance(claims['nonce'], str)
            or not hmac.compare_digest(claims['nonce'], nonce)
            or claims.get('azp', config['client_id']) != config['client_id']):
        raise ValueError('Identity not permitted')
    return claims


def make_blueprint(config):
    bp = Blueprint('oidc', __name__)
    pending = Pending()
    if config:
        validate_settings(config)

    def ready():
        local = auth_manager.load_auth_config()
        return bool(config and local.get('enabled') and local.get('configured')
                    and not local.get('declined') and local.get('password_hash')
                    and local.get('username') == config['local_username'])

    def response_cookie(response, value='', age=0):
        response.set_cookie(COOKIE, value, max_age=age, secure=True,
                            httponly=True, samesite='Lax', path='/')
        return response

    @bp.after_request
    def private_response(response):
        response.headers['Cache-Control'] = 'no-store'
        response.headers['Referrer-Policy'] = 'no-referrer'
        return response

    @bp.get('/api/auth/oidc/status')
    def status():
        return jsonify(enabled=ready())

    @bp.get('/api/auth/oidc/start')
    def start():
        if not ready() or request.host_url.rstrip('/') != config['origin']:
            return jsonify(error='OIDC unavailable'), 404
        try:
            meta = metadata(config)
            verifier, nonce, state = [secrets.token_urlsafe(48) for _ in range(3)]
            challenge = base64.urlsafe_b64encode(hashlib.sha256(verifier.encode()).digest()).rstrip(b'=').decode()
            handle = pending.put({'state': state, 'nonce': nonce, 'verifier': verifier, 'meta': meta})
            query = urlencode(dict(client_id=config['client_id'], redirect_uri=config['origin'] + CALLBACK,
                                   response_type='code', scope='openid email profile', state=state,
                                   nonce=nonce, code_challenge=challenge, code_challenge_method='S256'))
            return response_cookie(redirect(meta['authorization_endpoint'] + '?' + query), handle, 300)
        except Exception:
            return jsonify(error='OIDC unavailable'), 503

    @bp.get(CALLBACK)
    def callback():
        if not ready() or request.host_url.rstrip('/') != config['origin']:
            return jsonify(error='OIDC unavailable'), 404
        try:
            transaction = pending.take(request.cookies.get(COOKIE, ''))
            if (len(request.args.getlist('state')) != 1 or len(request.args.getlist('code')) != 1
                    or request.args.get('error') or len(request.args['code']) > 4096
                    or not hmac.compare_digest(request.args['state'], transaction['state'])):
                raise ValueError('Invalid callback')
            if request.args.get('iss', config['issuer']) != config['issuer']:
                raise ValueError('Invalid issuer')
            meta = transaction['meta']
            token = json_request('POST', meta['token_endpoint'],
                                 auth=(config['client_id'], config['client_secret']),
                                 data={'grant_type': 'authorization_code', 'code': request.args['code'],
                                       'redirect_uri': config['origin'] + CALLBACK,
                                       'code_verifier': transaction['verifier']})
            claims = validate_identity(token.get('id_token'), json_request('GET', meta['jwks_uri']),
                                       config, transaction['nonce'])
            # Existing app bearer-token/session machinery; no ID/access token
            # is returned to the browser or placed in a URL.
            local_token = auth_manager.generate_token(config['local_username'],
                                                      expires_at=min(claims['exp'], int(time.time()) + 3600))
            if not local_token:
                raise ValueError('Session unavailable')
            handle = pending.put({'token': local_token}, ttl=30)
            return response_cookie(redirect(config['origin'] + '/'), handle, 30)
        except Exception:
            return response_cookie(jsonify(error='OIDC sign-in denied')), 401

    @bp.post('/api/auth/oidc/complete')
    def complete():
        # This unauthenticated authentication endpoint requires an exact origin
        # and a single-use HttpOnly browser-bound handoff, not a forwarded user.
        if not ready() or request.headers.get('Origin') != config['origin']:
            return jsonify(error='OIDC sign-in denied'), 403
        try:
            handoff = pending.take(request.cookies.get(COOKIE, ''))
            return response_cookie(jsonify(success=True, token=handoff['token']))
        except Exception:
            return response_cookie(jsonify(error='No completed sign-in')), 401

    return bp
