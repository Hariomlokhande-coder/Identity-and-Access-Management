# Identity & Access Management Platform

A centralised identity service: applications delegate authentication, token issuance
and authorization to it instead of each building their own login.

Java 21 · Spring Boot 3.3 · PostgreSQL · Redis · JWT (RS256) · OAuth2 / OpenID Connect

---

## Running it

Install JDK 21, Maven, and Docker. Start from the repository root.

```bash
cd backend
docker compose up -d  # PostgreSQL :15432, Redis :6379, Mailpit SMTP :1025 and UI :8025
mvn spring-boot:run                  # starts on :8080 with the dev profile
```

Flyway creates the schema and seeds the baseline roles and permissions on first start.

To get an administrator, set both variables and start with an empty database:

```bash
IAM_BOOTSTRAP_ADMIN_EMAIL=admin@localhost \
IAM_BOOTSTRAP_ADMIN_PASSWORD='Ch4nge-me-now!' mvn spring-boot:run
```

Nothing is created unless both are set and the `users` table is empty, so a forgotten
default password can never become a backdoor.

- API docs: <http://localhost:8080/swagger-ui.html>
- Discovery: <http://localhost:8080/.well-known/openid-configuration>

### Tests

```bash
mvn test      # unit tests only (no Docker needed)
mvn verify    # adds the integration tests (needs Docker for Testcontainers)
```

The integration tests run against real PostgreSQL and Redis containers. Neither is
mocked, because the behaviour that matters most - the conditional `UPDATE` that makes
refresh rotation safe, and the Redis markers that make revocation immediate - only
exists there.

### Exploring the codebase

The repository ships a [graphify](https://github.com/Graphify-Labs/graphify) knowledge
graph, which is faster than grepping when you need to know what a change will break.

```bash
pip install "graphifyy[sql]" && graphify install   # once; [sql] includes the migrations
graphify update .                                  # build or refresh the graph
```

Then open `graphify-out/graph.html` **in a browser** - opening it in an editor only
shows the HTML source. Click a node to see its edges, or filter by community.

```bash
graphify explain "TokenRevocationStore"   # one node and everything it touches
graphify affected "SessionService"        # what breaks if this changes
graphify god-nodes --top 15               # the architectural hubs
graphify query "how does refresh rotation work"
```

Extraction is local tree-sitter AST parsing - no LLM, no API key, nothing leaves the
machine. Re-run `graphify update .` after changing code; add `--force` after a refactor
that deleted files, since the rebuild is otherwise refused when the node count drops.
Documentation changes need the semantic pass (`/graphify .` in an AI assistant), and
`graphify label .` names communities with an LLM if one is configured.

`graphify-out/` is generated and git-ignored.

---

## Production configuration

Two settings must be changed before any real deployment.

**Signing keys.** By default the platform refuses to start without one; a dev-only
ephemeral key is available behind `iam.jwt.allow-ephemeral-key`. Generate a key with:

```bash
./scripts/generate-jwt-key.sh key-2026-01
```

and pass the JSON as `IAM_JWT_KEYS`. See [backend/.env.example](backend/.env.example) for the full variable list.

**Key rotation** works because `IAM_JWT_KEYS` is a list: every listed key verifies, and
the one marked `active` signs.

1. Add the new key with `"active": false` and deploy. All instances can now verify it.
2. Flip `active` to the new key and deploy. New tokens use it; old tokens still verify.
3. Once no token signed by the old key can still be alive (access-token TTL plus clock
   skew), remove it.

Skipping the overlap breaks every token in flight the moment the key changes.

---

## Architecture

```
                    ┌─────────────────────────────────────────┐
   Browser ───────▶ │  Filter chain                           │
   App server ────▶ │  correlation id → JWT auth → SSO cookie │
                    │  auth → rate limit → method security    │
                    └────────────────┬────────────────────────┘
                                     │
   ┌──────────┬───────────┬──────────┴──────┬──────────┬────────────┐
   │ /auth    │ /oauth2   │ /users /roles   │ /clients │ /sessions  │
   └──────────┴───────────┴─────────────────┴──────────┴────────────┘
                                     │
              ┌──────────────────────┴──────────────────────┐
              │                                             │
        PostgreSQL                                        Redis
   users, roles, clients,                      rate limits, lockout counters,
   sessions, token metadata,                   revocation markers, auth codes,
   consent, audit, mail outbox                 pending authorize requests
        (source of truth)                        (short-lived, derived)
```

Redis holds nothing the platform cannot rebuild or afford to lose. Every entry there
expires on its own, and the identity that matters lives in PostgreSQL.

One package per capability, each owning its entities, service and controller:

```
com.iamplatform
├── auth/          registration, login, password flows
│   ├── token/     JWT signing, refresh rotation, revocation markers
│   └── credential/ single-use verification and reset tokens
├── oauth/         authorize, token, consent, userinfo, discovery
├── user/          profile and administration
├── role/          roles and permissions (RBAC)
├── client/        application registry
├── session/       device sessions
├── security/      filters, rate limiting, lockout, authority resolution
├── email/         transactional outbox and dispatcher
├── audit/         security event trail
├── maintenance/   expired-data cleanup
├── exception/     one error shape for the whole API
└── config/        properties and the security filter chain
```

---

## How the hard parts work

### Refresh token rotation under concurrency

Two tabs, or one retried request, send the same refresh token at the same moment. Both
find an active row. Correctness comes from one statement:

```sql
UPDATE refresh_tokens SET revoked_at = now() WHERE id = ? AND revoked_at IS NULL
```

PostgreSQL serialises both requests on that row, so exactly one sees `NULL` and updates
one row. The request that updates zero rows knows the token was already spent.

There is no way to tell that loser from a genuine replay by a thief, so both are
treated the same way: the whole token family and its session are revoked and everyone
signs in again. Revocation runs in its own transaction, because the request that
detected the reuse then fails, and a rollback would undo the very revocation it
triggered.

No distributed lock is involved. The database constraint is the source of truth.

### Making a stateless token stop working

A JWT cannot be deleted, so logout leaves a short-lived marker in Redis that every
instance consults. Three markers cover everything:

| Marker | Written by | Effect |
| --- | --- | --- |
| token id | logout | that one access token stops being accepted |
| session id | session or device revocation | every token from that session dies |
| minimum permission version | role change, password change, disable, delete | every token minted before the change dies |

Access tokens carry the permission version they were signed with, so raising the floor
invalidates the old ones without a database read on the hot path. Each marker only has
to outlive the longest access token still in flight, so they all expire by themselves.

Reads fail closed. If Redis is unreachable the platform cannot prove a token was *not*
revoked, so it answers 503 rather than accepting it.

### Live permission changes

`iam.security.permission-check-mode` picks the trade-off:

- `TOKEN` (default) trusts the authorities inside the token. One signature check per
  request, and the permission-version marker keeps the stale window at zero for changes
  the platform makes itself.
- `LIVE` reloads roles and account state from the database on every request. No stale
  window at all, at the cost of one query per call.

### Not leaking who has an account

Registration, forgot-password and resend-verification return one fixed response for
every input. Login returns one rejection for both a wrong password and an unknown
address - and the unknown path still performs a full BCrypt verification against a
decoy hash, so it is not measurably faster.

Specific reasons (unverified, disabled) appear only *after* the password has been
proven correct, at which point the caller already knows the account exists.

Lockout counters are keyed on the submitted address whether or not it exists.
Otherwise an attacker could learn which addresses are real by seeing which ones start
answering "locked".

### Redirect URIs and authorization codes

Registered URIs are matched by exact string comparison. Prefix matching is what turns
an authorize endpoint into a delivery service for other people's codes. Registration
rejects wildcards, fragments, relative URIs and plain HTTP outside loopback.

Until a redirect URI has been matched, protocol errors are rendered directly rather
than redirected - sending a browser to an unverified URI would be an open redirect.
After that point errors go back to the client as `error` plus `state`, as the spec
requires.

Codes are consumed with Redis `GETDEL`, so a replay finds nothing no matter how fast it
arrives, and are stored by hash so a keyspace dump cannot be replayed. PKCE with S256
is mandatory for public clients; `plain` is not supported, because it sends the secret
through the same channel as the code and proves nothing.

Consent requests are parked server-side. When the consent screen answers, the scopes,
redirect URI and PKCE challenge are read from the parked request, so a tampered form
cannot approve something the user never saw.

### Cross-application isolation

A role either belongs to a client application or is platform-wide. Tokens are minted
for one audience, and only roles applying to that audience become authorities - so an
admin of the shop is nobody in the bank, even though the same key signed both tokens.

The platform's own API accepts only tokens with audience `iam`. A token issued to an
application opens `/oauth2/userinfo` and that application's APIs, and nothing here.

### Mail that cannot fail a registration

Mail is written to an outbox table inside the same transaction as the business change
and delivered by a background dispatcher with capped exponential backoff. A dead SMTP
server delays a message; it never rolls back a registration or a password reset. Batches
are claimed with `SKIP LOCKED`, so several instances drain the same queue without
sending anything twice.

---

## Integrating an application

1. An administrator registers the application: `POST /clients`. The client secret is
   returned once and stored only as a hash.
2. Point the application at the issuer. It reads
   `/.well-known/openid-configuration` and fetches keys from `/oauth2/jwks`, so key
   rotation needs no change on its side.
3. Send the user to `/oauth2/authorize` with `response_type=code`, `client_id`,
   `redirect_uri`, `scope`, `state` and a PKCE `code_challenge`.
4. Exchange the returned code at `/oauth2/token` with the `code_verifier`.
5. Verify tokens locally: signature against JWKS, plus `iss`, `exp`, and `aud` equal to
   your own `client_id`. Pin RS256 rather than reading `alg` from the token header.
6. Apply your own business authorization on top of the permissions in the token.

---

## API

### Authentication
| Method | Path | Notes |
| --- | --- | --- |
| POST | `/auth/register` | fixed generic response |
| POST | `/auth/verify-email` | single-use link |
| POST | `/auth/resend-verification` | supersedes the previous link |
| POST | `/auth/login` | returns access + refresh token, sets the SSO cookie |
| POST | `/auth/refresh` | rotates; a replay revokes the family |
| POST | `/auth/logout` | optionally all devices |
| POST | `/auth/forgot-password` | fixed generic response |
| POST | `/auth/reset-password` | revokes every session |
| POST | `/auth/change-password` | requires the current password |

### OAuth2 / OIDC
`GET /oauth2/authorize` · `GET|POST /oauth2/consent` · `POST /oauth2/token` ·
`GET /oauth2/userinfo` · `GET /oauth2/jwks` · `GET /.well-known/openid-configuration` ·
`GET /oauth2/consents` · `DELETE /oauth2/consents/{id}`

`POST /oauth2/consent` answers a browser navigation with a 302 back to the client. A
caller that sends `Accept: application/json` gets `{"redirectUri": "..."}` instead and
performs the navigation itself — a script cannot use the 302, because `fetch` and
`XMLHttpRequest` follow it themselves into a cross-origin request the client answers
without CORS headers, consuming the authorization code on the way.

### Hosted screens

`/oauth2/authorize` does not render a login or consent page. It redirects to the URLs
in `iam.login-url` and `iam.consent-url`, passing `return_to` (the whole authorize
request, to be replayed) or `request_id` respectively. Configure those URLs to point to your hosted login and consent screens.

### Users · Roles · Clients · Sessions
| Method | Path | Requires |
| --- | --- | --- |
| GET | `/users/me` | authenticated |
| PUT | `/users/me/email` | authenticated |
| GET | `/users/{id}` | `USER_READ` or self |
| GET | `/users` | `USER_READ` |
| POST | `/users` | `USER_CREATE` |
| PUT | `/users/{id}/email` `/status` `/roles` | `USER_UPDATE` |
| POST | `/users/{id}/unlock` | `USER_UPDATE` |
| DELETE | `/users/{id}` | `USER_DELETE` |
| GET | `/roles` `/roles/{id}` `/roles/permissions` | `ROLE_READ` |
| POST | `/roles` · PUT `/roles/{id}/permissions` · DELETE `/roles/{id}` | `ROLE_MANAGE` |
| GET | `/clients` `/clients/{id}` | `CLIENT_READ` |
| POST | `/clients` · PUT `/clients/{id}` · POST `/clients/{id}/rotate-secret` · DELETE | `CLIENT_MANAGE` |
| GET | `/sessions` · DELETE `/sessions/{id}` · DELETE `/sessions/all` | authenticated (own) |
| DELETE | `/sessions/users/{userId}` | `SESSION_ADMIN` |
| GET | `/audit/events` | `AUDIT_READ` |

### Errors

Every endpoint returns the same shape:

```json
{
  "timestamp": "2026-09-03T12:00:00Z",
  "status": 403,
  "code": "FORBIDDEN",
  "message": "You are not allowed to perform this action",
  "path": "/users",
  "correlationId": "3f1c...",
  "details": {}
}
```

`400` invalid input · `401` missing, invalid or expired credentials · `403`
authenticated but not allowed · `404` · `409` conflict · `429` rate limited, with
`Retry-After` · `500` · `503` a dependency is down, with `Retry-After`.

OAuth2 endpoints instead return the spec format (`error`, `error_description`), because
client libraries parse those fields.

---

## Behaviour under failure

| Failure | Behaviour |
| --- | --- |
| Redis down | Fails closed on rate limiting, lockout and revocation checks: 503. Nothing that needs a security decision proceeds without one. |
| Database down | 503 with `Retry-After`. Authentication never falls back to something weaker. |
| Mail provider down | Queued and retried with backoff. The user-facing operation still succeeds. |
| Key rotation | Old and new keys verify simultaneously; in-flight tokens keep working. |
| Instance restart | Stateless instances; sessions and tokens live in PostgreSQL and Redis. |

---

## Deliberate limitations

- **Rate limiting is a fixed window.** Simple and correct at the boundary, but it
  permits a burst spanning two adjacent windows. A sliding window is the upgrade if
  that matters.
- **CSRF relies on SameSite plus JSON.** The API is bearer-authenticated, and the one
  cookie-authenticated endpoint (consent) is protected by `SameSite=Lax` and a JSON
  body requirement. A synchroniser token would be needed if cookie-authenticated
  state-changing endpoints were added.
- **Single-tenant.** Roles scope per client, not per organisation. Multi-tenancy would
  need a tenant column on users, roles and clients, and a tenant claim in the token.
- **No CAPTCHA.** The platform reports when one should be demanded
  (`iam.lockout.captcha-after-attempts`); presenting and verifying it is the login
  screen's job.
- **Password breach checking is off by default** and fails open when enabled. It is a
  password-quality gate, not an authentication control, so a third-party outage must
  not stop people registering.
