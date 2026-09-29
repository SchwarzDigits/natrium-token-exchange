# Operations

## Running

The service needs no database and no other service than the Wire backend. It keeps no state, so any number of
instances can run side by side with the same configuration. The configuration is in the
[README](../README.md#configuration).

Expose only `/v1/token` and `/.well-known/jwks.json`. The storage server and the PIN service need
`/.well-known/jwks.json`; if they run in the same cluster, they can fetch it there, and the key set does not have to be
public at all.

`STORAGE_AUDIENCE` and `PIN_AUDIENCE` must be the names the storage server and the PIN service expect as `aud`, and
they must differ. Without `PIN_AUDIENCE` the service issues no PIN tokens.

On Linux the service makes its process not dumpable and turns off core dumps at start: the signing keys are in its
memory and its environment, and another process of the same user can then read neither through `/proc`.

### Limits by address

The service limits per user, after the token check, and bounds the checks that run at once. It does not limit per
client address, because behind a reverse proxy it cannot tell addresses apart reliably. Limit requests per address at
the ingress in front of it, e.g. with `limit-rps` of the NGINX ingress controller. A client needs a few requests per
hour; 1 request per second with a burst of 10 per address leaves ample room.

## Signing keys

A signing key is an Ed25519 seed of 32 bytes with a key ID. `new-signing-key -key-id <id>` creates one and prints its
entry, `<key ID>:<base64url seed>`. The entry is a secret: whoever has it can issue tokens. Keep it where the
deployment keeps its secrets, and pass it in `NATRIUM_TOKEN_EXCHANGE_SIGNING_KEYS`.

A key ID has 1 to 64 characters from `A-Z`, `a-z`, `0-9`, `-` and `_`. A date works well, e.g. `2026-09`.

### Rotating the signing keys

The servers cache the key set for up to five minutes, and tokens live for `STORAGE_TOKEN_TTL` or `PIN_TOKEN_TTL`. A
rotation therefore has three steps:

1. **Publish.** Create a new key and add it to `SIGNING_KEYS`, leaving `CURRENT_KEY_ID` at the old key. Deploy, then
   wait at least five minutes, so that every server knows the new key.
2. **Switch.** Set `CURRENT_KEY_ID` to the new key and deploy. New tokens are signed with it.
3. **Retire.** After at least the longer of the two lifetimes, when no token of the old key is left, remove the old
   key from `SIGNING_KEYS` and deploy.

### A leaked signing key

Whoever has a signing key can issue tokens for any user and any key, and so store databases on the storage server.
They cannot read other clients' databases: those belong to other keys and are encrypted. To react:

1. Create a new key, set `SIGNING_KEYS` to only the new key and `CURRENT_KEY_ID` to it, and deploy.
2. Clients whose token is refused ask for a new one and reconnect. Tokens of the leaked key stop working once the
   storage servers have fetched the new key set, within five minutes.

## Allowed and denied teams and users

`ALLOWED_TEAMS`, `DENIED_TEAMS`, `ALLOWED_USERS` and `DENIED_USERS` decide who gets tokens; the rules and examples are
in the [README](../README.md#configuration) and in [protocol.md](protocol.md#admission). A change takes effect when the
service restarts. A user who loses the admission keeps a token already issued until it expires, at most
`STORAGE_TOKEN_TTL`; the storage server ends the connection at that time, and the next token is refused. The log at start shows the size of
each list, or `*`.

## Limits per user

`TOKEN_LIMIT` and `KEY_LIMIT` bound what one user gets from one instance; the rules are in
[protocol.md](protocol.md#limits). The counts are in memory, so a restart resets them, and with several instances each
counts on its own. If users of a large team share one address, the per-address limit at the ingress, not these, is the
one to raise.

`MAX_CONCURRENT_WIRE_CHECKS` bounds the token checks with Wire per instance. A check normally takes a few tens of
milliseconds, so the default of 64 allows about a thousand requests per second per instance. Requests beyond it are
counted as `overloaded` in the metrics.

## Probes, metrics and logs

| Path | Behaviour |
|---|---|
| `/.well-known/live` | always `200 ok` |
| `/.well-known/ready` | `200 ok` while the server serves. The service has no store to wait for, and Wire is not checked: an outage of Wire affects every instance alike, and taking all of them out of service would not help. It shows as `503 unavailable` on the API and in the metrics instead |
| `/metrics` | Prometheus |

Metrics:

| Metric | Meaning |
|---|---|
| `natrium_token_exchange_requests_total{result}` | requests to `/v1/token` by result: `ok`, `bad_request`, `unauthorized`, `not_allowed`, `limited`, `overloaded`, `unavailable`, `internal` |
| `natrium_token_exchange_tokens_issued_total{audience}` | tokens issued, by audience: `storage`, `pin` |
| `natrium_token_exchange_wire_auth_duration_seconds` | duration of the token check with Wire |
| `natrium_token_exchange_limited_users` | users whose tokens or keys are counted against the limits |

The server logs one JSON line per request to `/v1/token` with the result, the user, the team, the audience, the
client's public key, the token's `jti` and, for a refusal by a limit, which limit (`tokens` or `keys`), as far as they are known. It never
logs the Wire token or the issued token.
