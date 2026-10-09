# Optional Authentik sign-in

This change is repository-only. It does not configure an identity provider,
publish a hostname, alter a running installation, or disable local recovery.
The configuration example contains placeholders, not deployed settings.

## Design and permission scope

Only the configured `(issuer, subject, verified email)` identity can sign in.
That identity maps explicitly to the existing local administrator. This grants
the same host-management capability as that local account, including terminal
and administrative actions. No account creation, group-based widening, or
automatic email-only linking is supported. Local password/TOTP login stays
available and must be configured and enabled before OIDC becomes available.
Local TOTP applies to local login. OIDC authentication factors are controlled
by the identity provider; this patch does not turn on or require MFA there.

Authorization code flow uses S256 PKCE, nonce and browser-bound, expiring,
single-use state. Discovery and signing-key requests require trusted HTTPS and
same-issuer-origin endpoints; credential-bearing redirects are rejected.
RS256 signature, exact issuer/audience, subject, email verification, nonce,
authorized party and token dates are validated before issuing a local session.
The local session lasts at most one hour or the remaining ID-token lifetime,
whichever is shorter. OIDC access/refresh/ID tokens are not persisted or sent
to the browser. A 30-second single-use HttpOnly cookie exchanges the completed
login for the existing application's bearer session via same-origin POST.

The existing browser bearer-token storage and logout behavior are retained.
Logout is local to ProxMenux; it does not end the Authentik session or revoke an
already copied bearer token. A fresh SSO attempt may therefore sign in without
another password. Do not describe this as global single logout.

## Operator setup (separate deployment approval required)

1. Back up the running application and private local authentication config.
2. Create a separate confidential Authentik client with strict authorization
   callback `https://monitor.example/api/auth/oidc/callback`, RS256 signing and
   `openid email profile` scopes. Bind only the intended owner. Use an email
   mapping backed by independent verification, never unconditional `True`.
3. Copy `AppImage/config/oidc.example.json` outside the checkout. Replace values
   privately, set its owner to the service account and permissions to `0600`.
   Set `PROXMENUX_OIDC_CONFIG` to this absolute file path in the service.
   Never commit that real file or submit its contents to chat or logs.
4. Use a canonical HTTPS origin with no trailing slash. The issuer must exactly
   match discovery, including its trailing slash. Reverse proxies must preserve
   the canonical Host and HTTPS request scheme. This patch does not enable
   blanket forwarded-header trust. Set proxy access logging to omit callback
   query strings; the built-in Flask/gevent logging redacts them.
5. Build and test the AppImage on its target Linux/Python ABI. RS256 requires
   the cryptography wheel; the build must fail if it is unavailable. Python
   dependencies must not be copied from a different interpreter ABI.
6. In an isolated browser test valid owner, wrong subject with same email,
   wrong email, unverified email, local recovery, logout, mobile and WebSocket
   behavior before considering activation complete. Preserve old access until
   those tests pass. No network route is created by this patch.

Pending transactions are bounded process-local memory. A restart invalidates
pending logins safely. Use one server process (the existing threaded/gevent
deployment); multiple worker processes need a shared single-use transaction
store before deployment. An IdP outage affects SSO only; use local recovery.

Rollback: remove `PROXMENUX_OIDC_CONFIG` and restart the reviewed application
build. Local authentication is unchanged. Remove a deployed client or route
only through its separately approved rollback procedure.

## Validation

Run `python -m unittest discover -s AppImage/scripts/tests -p test_oidc.py -v`.
Tests use ephemeral RSA keys, synthetic identities and mocked transport; they
do not assert real IdP, browser, or packaged Linux AppImage acceptance.

Repository validation (2026-10-09, Windows/Python 3.12):

- 15 OIDC tests and all 5 existing local-account setup tests pass.
- `npm ci --legacy-peer-deps --ignore-scripts` and `npm run build` pass.
- Strict TypeScript checking reports 272 errors, identical with the fork's
  original login component; none are in the changed login component. The
  existing Next.js build configuration skips type/lint validation.
- The 37 pre-existing Python tests have the same 1 failure and 7 errors with
  the fork's original backend files: Linux filesystem/import assumptions,
  Windows text decoding, and an unrelated network-script version assertion.
- The Linux AppImage build and real identity-provider/browser flows have not
  been executed. They remain activation prerequisites. The existing frontend
  lockfile also produces an npm vulnerability warning for Next.js 15.1.9;
  framework remediation is separate from this optional login change.

References: [PyJWT validation](https://pyjwt.readthedocs.io/en/stable/usage.html),
[Authentik OAuth2](https://docs.goauthentik.io/add-secure-apps/providers/oauth2/).
