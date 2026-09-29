# Operations

## Running

The service needs no database and no other service than the Wire backend. It keeps no state, so any number of
instances can run side by side with the same configuration. The configuration is in the
[README](../README.md#configuration).

Expose only `/v1/token` and `/.well-known/jwks.json`. The storage server needs `/.well-known/jwks.json`; if it runs in
the same cluster, it can fetch it there, and the key set does not have to be public at all.

## Signing keys

A signing key is an Ed25519 seed of 32 bytes with a key ID. `new-signing-key -key-id <id>` creates one and prints its
entry, `<key ID>:<base64url seed>`. The entry is a secret: whoever has it can issue tokens. Keep it where the
deployment keeps its secrets, and pass it in `NATRIUM_TOKEN_EXCHANGE_SIGNING_KEYS`.

A key ID has 1 to 64 characters from `A-Z`, `a-z`, `0-9`, `-` and `_`. A date works well, e.g. `2026-09`.

### Rotating the signing keys

The storage server caches the key set for up to five minutes, and tokens live for `TOKEN_TTL`. A rotation therefore
has three steps:

1. **Publish.** Create a new key and add it to `SIGNING_KEYS`, leaving `CURRENT_KEY_ID` at the old key. Deploy, then
   wait at least five minutes, so that every storage server knows the new key.
2. **Switch.** Set `CURRENT_KEY_ID` to the new key and deploy. New tokens are signed with it.
3. **Retire.** After at least `TOKEN_TTL`, when no token of the old key is left, remove the old key from
   `SIGNING_KEYS` and deploy.

### A leaked signing key

Whoever has a signing key can issue tokens for any user and any key, and so store databases on the storage server.
They cannot read other clients' databases: those belong to other keys and are encrypted. To react:

1. Create a new key, set `SIGNING_KEYS` to only the new key and `CURRENT_KEY_ID` to it, and deploy.
2. Clients whose token is refused ask for a new one and reconnect. Tokens of the leaked key stop working once the
   storage servers have fetched the new key set, within five minutes.

## Allowed and denied teams and users

`ALLOWED_TEAMS`, `DENIED_TEAMS`, `ALLOWED_USERS` and `DENIED_USERS` decide who gets tokens; the rules and examples are
in the [README](../README.md#configuration) and in [protocol.md](protocol.md#admission). A change takes effect when the
service restarts. A user who loses the admission keeps a token already issued until it expires, at most `TOKEN_TTL`;
the storage server ends the connection at that time, and the next token is refused. The log at start shows the size of
each list, or `*`.

## Probes, metrics and logs

| Path | Behaviour |
|---|---|
| `/.well-known/live` | always `200 ok` |
| `/.well-known/ready` | `200 ok` while the server serves. The service has no store to wait for, and Wire is not checked: an outage of Wire affects every instance alike, and taking all of them out of service would not help. It shows as `503 unavailable` on the API and in the metrics instead |
| `/metrics` | Prometheus |

Metrics:

| Metric | Meaning |
|---|---|
| `natrium_token_exchange_requests_total{result}` | requests to `/v1/token` by result: `ok`, `bad_request`, `unauthorized`, `not_allowed`, `unavailable`, `internal` |
| `natrium_token_exchange_wire_auth_duration_seconds` | duration of the token check with Wire |

The server logs one JSON line per request to `/v1/token` with the result, the user, the team, the client's public key
and the token's `jti`, as far as they are known. It never logs the Wire token or the issued token.
