# Threat model

The service decides who may use the storage server. It is a gate against strangers filling the server with databases,
not the protection of the data: the databases are encrypted by the clients, and each belongs to the client key that
created it.

## What an attacker gains

| The attacker has | Result |
|---|---|
| a token of this service | Nothing without the private key it is bound to: the storage server asks for a proof of that key at every connection. The token expires after `TOKEN_TTL`. |
| a Wire access token of an admitted user | Tokens for keys of the attacker's choice, and with them space on the storage server, until the Wire token expires. Not the user's databases: they belong to the user's key. |
| a Wire access token of a user the lists do not admit | Nothing: `403`. |
| a signing key | Tokens for any user and any key, so space on the storage server, until the key is replaced (see [operations.md](operations.md#a-leaked-signing-key)). Not the data of other clients. |
| control of the running service | The signing keys, and the Wire access tokens of the users who make requests, each valid for up to 15 minutes. |
| control of the Wire backend, or its token signing key | Wire tokens for any user, and with them tokens for the admitted users. The Wire backend is trusted. |
| a web page the user visits | Nothing. The page may call the API (CORS allows any origin), but the browser does not add the user's Wire token; without it the page gets `401`. |
| the logs | User IDs, teams, public keys and token IDs. No Wire token, no issued token. |

## Limits

- **No rate limit.** Every request asks Wire, and only admitted users get tokens. An admitted user can ask for many
  tokens and use many keys; the storage server has to bound the space per key.
- **Revocation takes a token lifetime.** A user who loses the admission, or is blocked in Wire, keeps an issued token
  until it expires. The storage server ends connections at the token's expiry, so the delay is at most `TOKEN_TTL`.
- **No proof of possession at the exchange.** A token can be requested for any public key. It is useless without the
  private key, which the storage server checks.
- **Memory.** The signing keys are in the memory of the running service, neither locked against swapping nor wiped.
  A leak lets an attacker pass the gate, not read data.
- **Availability.** Without the service, clients get no new tokens and cannot connect to the storage server once
  their token has expired. The service depends only on Wire.
