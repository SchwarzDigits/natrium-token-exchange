# Protocol

Two servers of Natrium admit a client only with a token of this service:

- a **sqlite-remote-server** stores the client's encrypted databases;
- the **natrium-pin-service** protects the client's key file with a PIN.

A client gets a token by presenting its Wire access token. The service checks it with Wire and issues a token only to
admitted users, for the server the client names. Neither server accepts Wire access tokens:

- The servers do not depend on Wire. They verify tokens offline with the public keys of this service.
- Only this service sees Wire access tokens, which act for the user at Wire. A server that is taken over does not
  hand them to an attacker.
- Only this service decides who is admitted, by team and by user.
- A storage token is bound to the client's key for the storage server, so a copied token is useless without that key.
- Each token names its server in `aud`, so a token for one server is refused by the other.

## Flow

For the storage server:

| Step | Party |
|---|---|
| log in to Wire, get an access token | client |
| `POST /v1/token` with the Wire token, the audience `storage` and the public key of the client's storage key | client |
| check the Wire token with `GET /self`, check the admission, issue a token | service |
| connect to the storage server, send the token in `Hello` and prove the key | client |
| verify the token with the key set and compare its key with the `Hello` key | storage server |

The client asks for a new token before the old one expires, at half its lifetime, and whenever the storage server
refuses a token. The storage server ends a connection when its token expires; the client reconnects with a new one.

For the PIN service, when the client makes or opens a key file:

| Step | Party |
|---|---|
| log in to Wire, get an access token | client |
| `POST /v1/token` with the Wire token and the audience `pin`, without a key | client |
| check the Wire token, check the admission, issue a token | service |
| call the PIN service with the token | client |
| verify the token with the key set and take the user from `sub` | PIN service |

A browser that restores its key file has no key yet: the key comes out of the key file. That is why a PIN token is
not bound to a key.

## API

### `POST /v1/token`

```
POST /v1/token
Authorization: Bearer <Wire access token>
Content-Type: application/json

{"audience": "storage", "publicKey": "11qYAYKxCrfVS_7TyWQHOg7hcvPapiMlrwIaaPcHURo"}
```

| Field | Meaning |
|---|---|
| `audience` | Required. `storage` for a token for the storage server, `pin` for a token for the PIN service. `pin` exists only if the service is configured with a PIN audience. |
| `publicKey` | Required for `storage`, not allowed for `pin`. The client's Ed25519 public key for the storage server: 32 bytes in base64url without padding (RFC 4648, section 5), as in the `x` member of a JSON Web Key. It must be a point of the curve and not of small order. |

Answer `200`:

```json
{"token": "eyJhbGciOiJFZERTQSIsImtpZCI6IjIwMjYtMDkiLCJ0eXAiOiJKV1QifQ.…", "expiresIn": 3600}
```

`expiresIn` is the lifetime in seconds: one hour for `storage` and ten minutes for `pin` by default. Answers carry
`Cache-Control: no-store`.

The service does not ask for a proof that the client holds the private key. The storage server asks for that proof at
every connection, so a token for someone else's key cannot be used.

### Errors

The body is always `{"error": "<code>"}`.

| Status | Code | When |
|---|---|---|
| 400 | `bad_request` | The body is larger than 1 KiB, is not exactly one JSON object, or has unknown fields; `audience` is missing or unknown; for `storage`, `publicKey` is missing, is not base64url without padding, is not 32 bytes or is not a usable Ed25519 public key; for `pin`, `publicKey` is present. |
| 401 | `unauthorized` | The header `Authorization: Bearer <token>` is missing, or Wire rejects the token. The answer carries `WWW-Authenticate: Bearer`. |
| 403 | `not_allowed` | The lists of allowed and denied teams and users do not admit the user (see Admission). |
| 429 | `too_many_requests` | The user reached a limit (see Limits). `Retry-After` gives the seconds until the request would be allowed, rounded up. |
| 503 | `unavailable` | Wire could not be asked or gave no usable answer, or too many token checks run at once; in that case the answer carries `Retry-After: 1` and Wire was not asked. |
| 500 | `internal` | An error in the server. |
| 405 | – | Another method than `POST`. |

The server checks in this order:

1. token (a request to Wire, unless too many checks run at once),
2. admission,
3. body: audience and key,
4. limits: count the token if it is within the limits,
5. issue.

### `GET /.well-known/jwks.json`

The public keys as a JSON Web Key Set (RFC 7517), one Ed25519 key (RFC 8037) per signing key:

```json
{"keys": [
  {"kty": "OKP", "crv": "Ed25519", "x": "…", "kid": "2026-09", "alg": "EdDSA", "use": "sig"},
  {"kty": "OKP", "crv": "Ed25519", "x": "…", "kid": "2026-12", "alg": "EdDSA", "use": "sig"}
]}
```

It carries `Cache-Control: public, max-age=300`. During a rotation it holds the old and the new key; see
[operations.md](operations.md#rotating-the-signing-keys).

## Tokens

A token is a JSON Web Token (RFC 7519) in compact serialization, signed with EdDSA over Ed25519 (RFC 8037).

Header:

```json
{"alg": "EdDSA", "kid": "2026-09", "typ": "JWT"}
```

Claims:

| Claim | Value |
|---|---|
| `iss` | the configured issuer, e.g. `https://token.example` |
| `aud` | the configured audience of the requested kind: the storage server, e.g. `wss://vfs.example/v1/ws`, or the PIN service, e.g. `https://pin.example`. A single string |
| `sub` | the user's qualified ID from `GET /self`, `<uuid>@<domain>` in lowercase |
| `team` | the user's team, a lowercase UUID. Absent for a user without a team |
| `cnf` | storage tokens only: the client's key (RFC 7800), `{"jwk": {"kty": "OKP", "crv": "Ed25519", "x": "<publicKey>"}}` |
| `iat`, `nbf` | the time of issue, in seconds since the epoch |
| `exp` | `iat` plus the configured lifetime of the kind |
| `jti` | a random ID of 16 bytes in base64url, for logs |

## Verification by the storage server

The storage server accepts a token only if all of the following hold:

1. The header's `alg` is `EdDSA`. Other algorithms, `none` in particular, are refused.
2. The key set contains the header's `kid`, and the signature verifies with that key.
3. `iss` is the configured issuer and `aud` is the server's own name.
4. `nbf` and `exp` hold at the server's clock, with a small allowance for clock skew.
5. `cnf.jwk` is an Ed25519 key whose `x` is the public key of the connection's `Hello`, and the client proves it holds
   the private key.

The server loads the key set from `/.well-known/jwks.json` and keeps it no longer than its `max-age`, which the
rotation of the signing keys relies on. A token with an unknown `kid` should make it fetch the key set again, at most
once per minute.

## Verification by the PIN service

The PIN service checks 1 to 4 in the same way, with its own name as `aud`, and takes the user from `sub`. It does not
look at `cnf`. Since the storage audience and the PIN audience differ, neither server accepts a token of the other.

## Admission

The service asks `GET /self` of the configured Wire backend with the token, and takes the user from `qualified_id` and
the team from `team`. It does not cache the answer; 401 and 403 from Wire mean the token is rejected, anything else
that is not a usable 200 counts as Wire being unavailable. It does not follow redirects, so the token goes only to the
configured backend.

Four lists decide who is admitted: allowed teams, denied teams, allowed users and denied users. The team lists hold
team UUIDs, the user lists qualified IDs `<uuid>@<domain>`, and each may hold `*` for all. The most specific entry
that matches the user decides, and at the same specificity a denial wins:

1. the user's own qualified ID in the denied users, then in the allowed users;
2. the user's team in the denied teams, then in the allowed teams;
3. `*` in the denied teams, then in the allowed teams, for a user who has a team;
4. `*` in the denied users, then in the allowed users;
5. otherwise the user is not admitted.

A user without a team matches no team entry. So allowed teams `*` with a few denied teams admits the members of every
other team and nobody without a team; allowed users `*` also admits users without a team.

The lists are part of the configuration; a change takes effect when the service is restarted, and for tokens already
issued once they expire.

## Limits

Each instance counts per user, in memory:

- **Tokens:** at most `TOKEN_LIMIT` tokens of both audiences in a sliding window, 60 per hour by default. A client
  renews its storage token at half its lifetime, so one device needs about two per hour; the rest is room for
  reloads, reconnects and key files. The PIN service limits the PIN guesses on its own.
- **Keys in use:** at most `KEY_LIMIT` distinct client keys, 10 per 24 hours by default. A key is in use from its
  last token until a whole window has passed. A client keeps one key per device, so this bounds how many storage
  identities, and with them how much space on the storage server, one user can open. PIN tokens have no key and do
  not count here.

A refused request is not counted. The counts are not shared between instances: with `n` instances a user can get up to
`n` times the limits.

Before any of this, each instance runs at most `MAX_CONCURRENT_WIRE_CHECKS` token checks with Wire at once. A request
beyond that is refused at once with `503` and `Retry-After: 1`, so a flood of requests, with valid tokens or not,
does not become a flood of requests to Wire.

## CORS

Pages of any origin may call the API. The server answers the preflight (`OPTIONS /v1/token`) with
`Access-Control-Allow-Origin: *`, `Access-Control-Allow-Methods: POST` and `Access-Control-Allow-Headers:
Authorization, Content-Type`, and answers requests and the key set with `Access-Control-Allow-Origin: *` and
`Access-Control-Expose-Headers: Retry-After`. It does not allow credentials.

A list of allowed origins would protect nothing here: CORS protects credentials that the browser adds by itself, such
as cookies, and the API has none. A page without the Wire token gets no further than 401.

## Client side

The client derives its storage key from its own secrets and never sends the private key. It asks for a storage token
after the Wire login and before it opens a database on the storage server, keeps the token in memory only, and hands
it to the storage connection whenever that connects. It renews the token at half its lifetime with a current Wire
access token. It asks for a PIN token right before it calls the PIN service, and for a new one when that has expired.

A `403` means the user may not use the servers; the client reports it as its own error rather than retrying. After a
`429` or a `503` it waits for `Retry-After` and uses its current token as long as it is valid.
