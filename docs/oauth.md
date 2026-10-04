# OAuth access tokens

Over [Streamable HTTP](streamable-http.md) the proxy can act as an **OAuth
protected resource**: clients present JWT access tokens issued by your
authorization server (Entra ID, Okta, Auth0, Keycloak, ...), and every call then
has a **principal**, someone it can be attributed to. That principal is
available in three places:

- **policy:** rules can match on `principal:` and `groups:`;
- **budgets:** `budgets.principal` gives every caller their own cap, instead of
  one pool that every client shares;
- **the audit log:** every call record carries a `principal` field.

The proxy validates tokens. It never issues them, never stores them and never
logs them.

## Configuration

The settings live in the policy file, because they are access policy and belong
next to the rules that use the identity:

```yaml
access:
  oauth:
    issuer: https://login.microsoftonline.com/<tenant>/v2.0
    audience: api://mcp-guardrails        # what a token's 'aud' must be
    required_scopes: [mcp.tools]          # every one must be granted
    principal_claim: preferred_username   # default: sub
    groups_claim: groups                  # default: groups
```

| Key | Default | Meaning |
| --- | --- | --- |
| `issuer` | required | The authorization server's issuer identifier, exactly as it appears in a token's `iss`. Must be https. |
| `audience` | required | The value a token's `aud` must contain. Without it, a token the same issuer minted for any other application would be accepted here. |
| `resource` | the request's URL | This proxy's public MCP endpoint, as advertised in the metadata. Unset, it is built from the request's scheme and `Host` header, so the client's own `Host` is echoed back in the challenge and the metadata (to that client only; it never affects which tokens are accepted). Set it when the proxy is behind a reverse proxy or TLS terminator, because clients check that it matches the URL they connected to. |
| `required_scopes` | none | Scopes every token must grant. A token missing one gets a 403 that names the scopes to ask for. Leaving it empty logs a startup warning: a scope the issuer grants only in access tokens is what shuts out ID tokens and tokens issued for other purposes. |
| `principal_claim` | `sub` | The claim whose value becomes the principal. A token without it is refused. |
| `groups_claim` | `groups` | The claim whose values a rule's `groups:` matches. |
| `jwks_uri` | discovered | Where the signing keys are, if the issuer does not publish discovery metadata. |
| `clock_skew_s` | `60` | Tolerance applied to `exp` and `nbf`, at most 300. |
| `jwks_refresh_s` | `3600` | How often the signing keys are refetched; at least 60. |
| `jwks_max_age_s` | `86400` | How long the last keys fetched stay in use while the issuer is unreachable; at most a week. |
| `require_at_jwt` | `false` | Refuse a token whose `typ` header is not `at+jwt` (RFC 9068). Leave it off for Entra ID, Okta and Auth0, which send `typ: JWT` by default; turn it on for an issuer that sends `at+jwt`, so nothing else it signs can pass for an access token. |
| `allow_insecure_localhost` | `false` | Allow plain `http://` for `issuer` and `jwks_uri`, and only on loopback. For a test authorization server on the same machine. |

Unknown keys are errors, like everywhere else in a security setting.

```bash
GUARDRAILS_POLICY=policy.yaml McpGuardrails.Cli --transport http --bind 0.0.0.0
```

OAuth counts as authentication, so a non-loopback `--bind` is accepted without
`GUARDRAILS_HTTP_TOKEN`. Put TLS in front of it anyway: the proxy speaks plain
HTTP.

## How a client gets in

The proxy implements the protected-resource half of the [MCP authorization
specification](https://modelcontextprotocol.io/specification/draft/basic/authorization):

1. A request with no token gets `401` and
   `WWW-Authenticate: Bearer resource_metadata="https://host/.well-known/oauth-protected-resource/mcp"`,
   plus `scope="..."` when scopes are required.
2. That URL serves the Protected Resource Metadata (RFC 9728): `resource`, the
   `authorization_servers` (your issuer), `scopes_supported`. It is public, and
   is also served at the bare `/.well-known/oauth-protected-resource`.
3. A compliant client takes it from there: discovers the authorization server,
   gets a token for this resource, and retries with `Authorization: Bearer ...`.

| Request | Answer |
| --- | --- |
| No token, or a scheme other than Bearer | `401`, challenge with `resource_metadata` |
| Malformed, forged, expired, wrong issuer or audience, no principal claim, an ID token | `401`, `error="invalid_token"` and a short fixed `error_description` |
| Valid, but missing a required scope | `403`, `error="insufficient_scope"`, the scopes to ask for |
| Valid | Passed on to the MCP endpoint, with the principal attached |
| Signing keys past `jwks_max_age_s` | `503`, no challenge: the client did nothing wrong |
| A non-loopback `Origin` | `403`, token or not, as without OAuth |

## What is checked

- **Signature**, against the issuer's published keys. Only RSA and EC signature
  keys are taken from the key set; a symmetric (`oct`) key is ignored, so no
  token can be signed with a shared secret that was published by mistake.
- **Algorithm:** RS256/384/512, PS256/384/512 or ES256/384/512. `none` and the
  HMAC family are never accepted, which rules out signing a token with the
  public key as if it were a shared secret.
- **`iss`** equals `issuer` exactly, and **`aud`** contains `audience`.
- **`exp`** is present and not past, **`nbf`** if present is not in the future,
  both with `clock_skew_s` of tolerance. A token that never expires is refused.
- **Scopes** are read from `scope` (space-separated, RFC 9068) and `scp` (Entra
  ID), as a string or an array.
- **The principal** is a non-empty string of at most 256 characters with no
  control characters, so it can go into the audit log safely.
- **Not an ID token:** a token carrying `nonce` is refused. When the client and
  the API share one app registration, an OpenID Connect ID token has the same
  issuer, audience and keys as an access token, and ID tokens are handled far
  more loosely (kept in browsers, logged). With `require_at_jwt`, `typ` must
  also be `at+jwt`.

Signature verification is done by `Microsoft.IdentityModel.JsonWebTokens`, the
library under every ASP.NET Core JWT bearer handler. A trimmed Native AOT publish
with it has no warnings. Fetching and caching the keys, and the lifetime, scope
and principal checks, are this repository's code
([`Access/`](../src/McpGuardrails.Core/Access/)), unit-tested against real
signatures.

## Signing keys

At startup the proxy reads the issuer's metadata — OpenID Connect discovery
(`{issuer}/.well-known/openid-configuration`), then RFC 8414
(`/.well-known/oauth-authorization-server{path}`) — and fetches the key set it
names. The metadata must name the configured issuer exactly, which stops one
server's metadata from pointing at another's keys.

| Situation | What happens |
| --- | --- |
| Keys cannot be fetched at startup | The proxy does not start (exit code 1). |
| `jwks_refresh_s` has passed | The next request refetches the keys. |
| A token names a key id the proxy has not seen | The keys are refetched, which is how rotation is picked up. At most once a minute, so made-up key ids cannot turn the proxy into a request flood against your issuer. |
| A refetch fails | The keys already fetched stay in use, and a warning is logged. |
| The keys are older than `jwks_max_age_s` | Every request gets `503` until a refetch succeeds. A key the issuer may have revoked is not trusted forever just because the issuer went quiet. |

Fetches never follow redirects, time out after 10 seconds and read at most 1 MB.

## Using the principal

```yaml
rules:
  - name: admins-may-delete
    match: { tool: "*__delete_*", groups: [mcp-admins] }
    decision: allow
  - name: nobody-else-deletes
    match: { tool: "*__delete_*" }
    decision: deny
  - name: contractors-read-only
    match: { principal: "*@contractor.example", annotations: { readOnlyHint: false } }
    decision: deny

budgets:
  principal: { max_calls: 500 }   # per caller, for the life of the process
  daily: { max_calls: 5000 }      # everyone together, per UTC day
```

`principal:` is a glob, like `tool:`, but matched **case-insensitively**.
Principals are often email addresses or UPNs, and identity providers emit them
in whatever case the account was created with, so a deny rule for
`*@contractor.example` has to catch `bob@Contractor.Example` too. For rules that
must not depend on a mutable, human-chosen name at all, use an immutable claim
such as `sub` or Entra's `oid` as `principal_claim`.

`groups:` matches when the caller is in any of the listed groups, by exact,
case-sensitive name: group claims are identifiers (Entra sends object IDs), and
copying the value from a token into the policy is the reliable way to write one.

A call without a principal matches no identity condition, the same way a call to
an unknown tool matches no `server:`. Because no call has a principal without
`access.oauth`, a policy that uses `principal:`, `groups:` or
`budgets.principal` without it is **refused at load**: a deny rule that can never
match is a guardrail that is not there.

`policy test` cases can name a caller with `principal:` and `groups:`; see
[testing a policy](policy.md#testing-a-policy).

## Refused combinations

These are startup errors, not guesses:

| Combination | Why |
| --- | --- |
| `access.oauth` and `GUARDRAILS_HTTP_TOKEN` | Two ways in is two policies about who may call. Exit code 2. |
| `access.oauth` over stdio | No call would carry a principal, so identity rules and budgets would never apply. Exit code 2. |
| `budgets.session` and `budgets.principal` | A session exists only over stdio and a principal only over HTTP; no transport enforces both. |

## Limits

- **Tokens are validated, not introspected.** A token revoked at the
  authorization server stays valid here until it expires. Keep access token
  lifetimes short.
- **Per-principal budgets live in memory** and reset when the proxy restarts.
  `budgets.daily` is persisted, but it is shared by everyone.
- **Groups come from the token.** Entra ID's group overage (a token with too
  many groups carries a link instead of the list) is not followed; use app
  roles (`groups_claim: roles`) for large tenants.
- **No DPoP or mTLS-bound tokens.** A stolen bearer token works until it
  expires, as with any bearer token.
