"""
A fixture OAuth authorization server for scripts/smoke.py, with no dependencies.

It does what the proxy needs from a real one (Entra ID, Okta, Auth0, Keycloak)
and nothing more: it serves OpenID Connect discovery metadata and a JSON Web Key
Set over plain HTTP on a loopback port, and it mints RS256 access tokens signed
with the matching private key, so the smoke test can present valid, expired,
mis-addressed and under-scoped tokens to a running proxy.

The RSA key is generated and the tokens signed in pure Python, because the CI
image has no cryptography package and a smoke test should not add one. That is
fine for a throwaway test key and nowhere else.
"""

import base64
import hashlib
import json
import secrets
import threading
import time
import urllib.parse
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

# DER prefix of a SHA-256 DigestInfo (RFC 8017 section 9.2, note 1).
_SHA256_PREFIX = bytes.fromhex("3031300d060960864801650304020105000420")


def _small_primes(limit: int = 2000) -> list[int]:
    sieve = bytearray([1]) * limit
    sieve[0:2] = b"\x00\x00"
    for i in range(2, int(limit**0.5) + 1):
        if sieve[i]:
            sieve[i * i :: i] = bytearray(len(sieve[i * i :: i]))
    return [i for i, prime in enumerate(sieve) if prime]


_SMALL_PRIMES = _small_primes()


def _is_probable_prime(n: int, rounds: int = 40) -> bool:
    if any(n % p == 0 for p in _SMALL_PRIMES):
        return n in _SMALL_PRIMES
    d, s = n - 1, 0
    while d % 2 == 0:
        d //= 2
        s += 1
    for _ in range(rounds):
        x = pow(secrets.randbelow(n - 3) + 2, d, n)
        if x in (1, n - 1):
            continue
        for _ in range(s - 1):
            x = pow(x, 2, n)
            if x == n - 1:
                break
        else:
            return False
    return True


def _prime(bits: int) -> int:
    while True:
        candidate = secrets.randbits(bits) | (1 << (bits - 1)) | (1 << (bits - 2)) | 1
        if _is_probable_prime(candidate):
            return candidate


def _b64url(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def _int_bytes(value: int, length: int | None = None) -> bytes:
    return value.to_bytes(length or (value.bit_length() + 7) // 8, "big")


class RsaKey:
    """A 2048-bit RSA key pair that can sign RS256."""

    def __init__(self, kid: str) -> None:
        self.kid = kid
        self.e = 65537
        while True:
            p, q = _prime(1024), _prime(1024)
            phi = (p - 1) * (q - 1)
            if p != q and phi % self.e:
                break
        self.n = p * q
        self.d = pow(self.e, -1, phi)
        self.size = (self.n.bit_length() + 7) // 8

    def jwk(self) -> dict:
        return {
            "kty": "RSA",
            "kid": self.kid,
            "use": "sig",
            "alg": "RS256",
            "n": _b64url(_int_bytes(self.n)),
            "e": _b64url(_int_bytes(self.e)),
        }

    def sign(self, message: bytes) -> bytes:
        """RSASSA-PKCS1-v1_5 with SHA-256 (RFC 8017 section 8.2)."""
        digest = _SHA256_PREFIX + hashlib.sha256(message).digest()
        padded = (
            b"\x00\x01" + b"\xff" * (self.size - len(digest) - 3) + b"\x00" + digest
        )
        return _int_bytes(pow(int.from_bytes(padded, "big"), self.d, self.n), self.size)


class FixtureIssuer:
    """An authorization server on a loopback port, and tokens to match.

    Serves discovery metadata and keys for a proxy validating tokens, and the
    endpoints an OAuth client needs to log in: dynamic client registration
    (RFC 7591), an authorization endpoint that approves at once and redirects
    back with a code, and a token endpoint that checks PKCE (RFC 7636) and
    honours refresh tokens until they are revoked.
    """

    #: The subject of every token the authorization endpoint issues.
    LOGIN_SUBJECT = "smoke-user"

    def __init__(self, *, audience: str = "", access_token_lifetime: int = 300) -> None:
        self.key = RsaKey("smoke-1")
        self.audience = audience
        self.access_token_lifetime = access_token_lifetime
        self.clients: dict[str, list[str]] = {}
        self.codes: dict[str, dict] = {}
        self.refresh_tokens: set[str] = set()
        self.token_requests: dict[str, int] = {
            "authorization_code": 0,
            "refresh_token": 0,
        }
        issuer = self

        class Handler(BaseHTTPRequestHandler):
            def do_GET(self) -> None:
                path, _, query = self.path.partition("?")
                if path in (
                    "/.well-known/openid-configuration",
                    "/.well-known/oauth-authorization-server",
                ):
                    self.reply(200, issuer.metadata())
                elif path == "/jwks":
                    self.reply(200, {"keys": [issuer.key.jwk()]})
                elif path == "/authorize":
                    self.authorize(urllib.parse.parse_qs(query))
                else:
                    self.send_error(404)

            def do_POST(self) -> None:
                length = int(self.headers.get("Content-Length", "0"))
                body = self.rfile.read(length).decode("utf-8")
                if self.path == "/register":
                    request = json.loads(body)
                    client_id = f"client-{secrets.token_hex(8)}"
                    issuer.clients[client_id] = request.get("redirect_uris", [])
                    self.reply(
                        201,
                        {
                            "client_id": client_id,
                            "redirect_uris": issuer.clients[client_id],
                            "token_endpoint_auth_method": "none",
                            "grant_types": ["authorization_code", "refresh_token"],
                            "response_types": ["code"],
                        },
                    )
                elif self.path == "/token":
                    form = {k: v[0] for k, v in urllib.parse.parse_qs(body).items()}
                    status, reply = issuer.exchange(form)
                    self.reply(status, reply)
                else:
                    self.send_error(404)

            def authorize(self, query: dict[str, list[str]]) -> None:
                def one(name: str) -> str:
                    return query.get(name, [""])[0]

                client_id, redirect_uri = one("client_id"), one("redirect_uri")
                if (
                    redirect_uri not in issuer.clients.get(client_id, [])
                    or one("code_challenge_method") != "S256"
                    or not one("code_challenge")
                ):
                    self.reply(400, {"error": "invalid_request"})
                    return
                code = secrets.token_urlsafe(16)
                issuer.codes[code] = {
                    "client_id": client_id,
                    "redirect_uri": redirect_uri,
                    "challenge": one("code_challenge"),
                    "scope": one("scope"),
                }
                location = (
                    f"{redirect_uri}?code={code}"
                    f"&state={urllib.parse.quote(one('state'))}"
                    f"&iss={urllib.parse.quote(issuer.url)}"
                )
                self.send_response(302)
                self.send_header("Location", location)
                self.send_header("Content-Length", "0")
                self.end_headers()

            def reply(self, status: int, body: dict) -> None:
                data = json.dumps(body).encode("utf-8")
                self.send_response(status)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(data)))
                self.end_headers()
                self.wfile.write(data)

            def log_message(self, format: str, *args: object) -> None:
                pass

        self._server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        self.url = f"http://127.0.0.1:{self._server.server_address[1]}"
        threading.Thread(target=self._server.serve_forever, daemon=True).start()

    def metadata(self) -> dict:
        return {
            "issuer": self.url,
            "jwks_uri": f"{self.url}/jwks",
            "authorization_endpoint": f"{self.url}/authorize",
            "token_endpoint": f"{self.url}/token",
            "registration_endpoint": f"{self.url}/register",
            "response_types_supported": ["code"],
            "grant_types_supported": ["authorization_code", "refresh_token"],
            "code_challenge_methods_supported": ["S256"],
            "token_endpoint_auth_methods_supported": ["none"],
        }

    def exchange(self, form: dict[str, str]) -> tuple[int, dict]:
        """The token endpoint: a code for tokens, or a refresh token for new ones."""
        grant = form.get("grant_type", "")
        if grant == "authorization_code":
            self.token_requests[grant] += 1
            code = self.codes.pop(form.get("code", ""), None)
            verifier = form.get("code_verifier", "")
            challenge = _b64url(hashlib.sha256(verifier.encode("ascii")).digest())
            if (
                code is None
                or code["client_id"] != form.get("client_id")
                or code["redirect_uri"] != form.get("redirect_uri")
                or code["challenge"] != challenge
            ):
                return 400, {"error": "invalid_grant"}
        elif grant == "refresh_token":
            self.token_requests[grant] += 1
            if form.get("refresh_token") not in self.refresh_tokens:
                return 400, {"error": "invalid_grant"}
        else:
            return 400, {"error": "unsupported_grant_type"}

        refresh = secrets.token_urlsafe(24)
        self.refresh_tokens.add(refresh)
        access = self.token(
            self.LOGIN_SUBJECT,
            audience=self.audience,
            scope="mcp.tools",
            expires_in=self.access_token_lifetime,
        )
        return 200, {
            "access_token": access,
            "token_type": "Bearer",
            "expires_in": self.access_token_lifetime,
            "refresh_token": refresh,
            "scope": "mcp.tools",
        }

    def revoke_refresh_tokens(self) -> None:
        self.refresh_tokens.clear()

    def token(
        self,
        subject: str,
        *,
        audience: str,
        scope: str | None = None,
        groups: list[str] | None = None,
        expires_in: int = 300,
    ) -> str:
        now = int(time.time())
        payload: dict = {
            "iss": self.url,
            "aud": audience,
            "sub": subject,
            "iat": now,
            "exp": now + expires_in,
        }
        if scope is not None:
            payload["scope"] = scope
        if groups is not None:
            payload["groups"] = groups
        header = {"alg": "RS256", "typ": "at+jwt", "kid": self.key.kid}
        signing_input = (
            _b64url(json.dumps(header).encode("utf-8"))
            + "."
            + _b64url(json.dumps(payload).encode("utf-8"))
        )
        signature = self.key.sign(signing_input.encode("ascii"))
        return f"{signing_input}.{_b64url(signature)}"

    def close(self) -> None:
        self._server.shutdown()
        self._server.server_close()
