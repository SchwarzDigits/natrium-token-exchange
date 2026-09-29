# Threat model

The service decides who may use the storage server. It is a gate against strangers filling the server with databases,
not the protection of the data: the databases are encrypted by the clients, and each belongs to the client key that
created it.

## What is protected

| Asset | Why it matters |
|---|---|
| the storage server's capacity | Without the gate, anyone could store databases on it. |
| the signing keys | Whoever has one can issue tokens and so pass the gate. |
| the Wire access tokens that clients send | They are valid for up to 15 minutes and act for the user at Wire. |
| the Wire backend | A flood of requests here must not become a flood of token checks there. |

## What an attacker gains

| The attacker has | Result |
|---|---|
| a token of this service | Nothing without the private key it is bound to: the storage server asks for a proof of that key at every connection. The token expires after `TOKEN_TTL`. |
| a Wire access token of an admitted user | Tokens until the Wire token expires, within the user's limits: `KEY_LIMIT` keys per instance, and so as many storage identities, each of which the storage server bounds in space. Not the user's databases: they belong to the user's key. |
| a Wire access token of a user the lists do not admit | Nothing: `403`. |
| many Wire access tokens, or none, sent at a high rate | No more than `MAX_CONCURRENT_WIRE_CHECKS` checks with Wire at once per instance; the rest is refused with `503` without asking Wire. The per-address limit at the ingress stops a single source earlier. |
| a signing key | Tokens for any user and any key, so space on the storage server, until the key is replaced (see [operations.md](operations.md#a-leaked-signing-key)). Not the data of other clients. |
| another process of the same Unix user on the host | Nothing through `/proc` or a debugger: the process is not dumpable. |
| control of the running service | The signing keys, and the Wire access tokens of the users who make requests, each valid for up to 15 minutes. |
| control of the Wire backend, or its token signing key | Wire tokens for any user, and with them tokens for the admitted users. The Wire backend is trusted. |
| a web page the user visits | Nothing. The page may call the API (CORS allows any origin), but the browser does not add the user's Wire token; without it the page gets `401`. |
| the logs | User IDs, teams, public keys and token IDs. No Wire token, no issued token. |

## Protections

- **Admission by team and user**, with allowed and denied lists; a user no entry matches is denied.
- **Tokens bound to a key** (RFC 7800 `cnf`), which the storage server checks against the proof of the key at every
  connection. A copied token is useless.
- **Short lifetime**, one hour by default, and connections that end with their token. A user who loses the admission
  is out after one token lifetime at the latest.
- **Limits per user**: tokens and distinct keys in use per window. They bound how many storage identities one account
  can open, which the storage server cannot see, since it knows keys, not users.
- **A bound on concurrent token checks**, so the service never passes more load to Wire than it is configured for.
- **Strict parsing**: bodies up to 1 KiB, one JSON object with known fields, public keys that are curve points not of
  small order.
- **Process protection** on Linux: not dumpable, no core dumps.
- **No token in logs, errors or metrics.**

## Limits

- **Counts per instance.** The limits are kept in memory. With `n` instances a user can get up to `n` times the
  limits, and a restart resets the counts. Sharing them would need a store the service does not have.
- **No limit per address in the service.** Behind a reverse proxy the service cannot tell client addresses apart
  reliably. The ingress in front of it has to limit per address.
- **Revocation takes a token lifetime.** A user who loses the admission, or is blocked in Wire, keeps an issued token
  until it expires. The storage server ends connections at the token's expiry, so the delay is at most `TOKEN_TTL`.
- **No proof of possession at the exchange.** A token can be requested for any public key. It is useless without the
  private key, which the storage server checks; it does use up one of the requester's keys in use.
- **Memory.** The signing keys are in the process's memory and environment, not locked against swapping and not
  wiped. A leak lets an attacker pass the gate, not read data.
- **Availability.** Without the service, clients get no new tokens and cannot connect to the storage server once
  their token has expired. The service depends only on Wire.
