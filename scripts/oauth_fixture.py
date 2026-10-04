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
    """Discovery metadata and keys on a loopback port, and tokens to match."""

    def __init__(self) -> None:
        self.key = RsaKey("smoke-1")
        issuer = self

        class Handler(BaseHTTPRequestHandler):
            def do_GET(self) -> None:
                if self.path == "/.well-known/openid-configuration":
                    body = {"issuer": issuer.url, "jwks_uri": f"{issuer.url}/jwks"}
                elif self.path == "/jwks":
                    body = {"keys": [issuer.key.jwk()]}
                else:
                    self.send_error(404)
                    return
                data = json.dumps(body).encode("utf-8")
                self.send_response(200)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(data)))
                self.end_headers()
                self.wfile.write(data)

            def log_message(self, format: str, *args: object) -> None:
                pass

        self._server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        self.url = f"http://127.0.0.1:{self._server.server_address[1]}"
        threading.Thread(target=self._server.serve_forever, daemon=True).start()

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
