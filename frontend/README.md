# IAM Console

The web front end for the Identity & Access Management platform in `../backend`.

It is two things at once. It is the platform's **hosted identity screens** — the login
and consent pages that `/oauth2/authorize` redirects a browser to, without which the
authorization code flow cannot complete. And it is the **console** — profile, devices,
connected apps, and the administration of users, roles, applications and the audit log.

Angular 21 (LTS), standalone components, signals, zoneless change detection.

---

## Running it

The backend must be running first. See `../README.md`.

```bash
npm install --legacy-peer-deps
npm start
```

Then open <http://localhost:3001>.

**The port is not arbitrary.** The backend ships with

```yaml
iam.login-url:   http://localhost:3001/login
iam.consent-url: http://localhost:3001/consent
iam.cors.allowed-origins: http://localhost:3001
```

so `/oauth2/authorize` redirects here by name, and 3001 is the only origin the CORS
policy permits credentials from. Serving on any other port means changing all three.

`--legacy-peer-deps` is needed because npm 10.9.8 crashes resolving `vitest`'s optional
`canvas` peer (`Cannot read properties of null (reading 'edgesOut')`). It is an npm bug,
not a dependency conflict.

---

## How it talks to the backend

| Concern | Where |
| --- | --- |
| Typed request/response models mirroring the Java DTOs | `src/app/core/models/` |
| One service per controller | `src/app/core/api/` |
| Bearer token, refresh-and-replay | `src/app/core/http/auth.interceptor.ts` |
| Error body parsing (both shapes) | `src/app/core/http/api-error.ts` |
| Route protection | `src/app/core/guards/auth.guard.ts` |

### Tokens

The access token is held **in memory only**. The refresh token is persisted in
`localStorage` so a page reload does not force a re-login — the accepted trade-off for
a token-authenticated SPA with no backend-for-frontend, bounded by the fact that the
server revokes the whole family the moment a rotated token is replayed.

### One refresh at a time

`AuthService.refresh()` shares a single in-flight request between all callers. This is
not an optimisation. The server treats a replayed refresh token as theft and revokes
the entire family, so two concurrent refreshes would not merely race — they would sign
the user out everywhere.

### Permissions in the UI

Navigation and buttons are filtered by the `perms` claim in the access token. This is a
courtesy so the console does not advertise screens that would 403. Every one of those
permissions is enforced again by `@PreAuthorize` on the server; nothing here is a
security control.

### return_to is validated

`/oauth2/authorize` hands the login screen the full authorize URL in `return_to`. That
value comes from the query string, so `safeReturnTo()` accepts only this origin or the
configured API origin. An unchecked redirect there would turn the identity provider's
own login page into an open redirect.

---

## Two backend changes this front end required

Both are in `../backend`, both additive, and the existing 51 tests still pass.

**1. `POST /oauth2/consent` can answer with JSON.** It previously always returned a 302
to the client's `redirect_uri`. A script cannot use that: `fetch` and `XMLHttpRequest`
follow redirects themselves, so the hop lands on a cross-origin URL that answers with no
CORS headers — the call fails and the authorization code is consumed on the way. Sending
`Accept: application/json` now returns `{"redirectUri": "..."}` and the consent screen
navigates itself. A browser navigation still gets the 302 exactly as before.

**2. `GET /oauth2/consents` now includes `clientApplicationId`.** The list returned the
public `client_id` string, but `DELETE /oauth2/consents/{clientApplicationId}` takes the
internal UUID — and resolving one to the other needs `CLIENT_READ`, which the user whose
consent it is has no reason to hold. The withdraw endpoint was unreachable from its own
list.

---

## Screens

**Identity provider** — these are what `iam.login-url` and `iam.consent-url` point at,
and they render without the console frame.

| Route | Purpose |
| --- | --- |
| `/login` | Sign in; replays `return_to` when it came from an authorize request |
| `/register` | Create an account (fixed generic response, no account enumeration) |
| `/verify-email` | Spends the emailed token; offers a fresh link when it has lapsed |
| `/forgot-password`, `/reset-password` | Reset flow; warns that a reset ends every session |
| `/consent` | Approve or deny an authorization request, by `request_id` |

**Account** — `/account/profile`, `/account/security`, `/account/sessions`,
`/account/apps`.

**Administration** — `/admin/users` (+ `/admin/users/:id`), `/admin/roles`,
`/admin/clients`, `/admin/audit`. Each is gated on the permission its endpoints require.

---

## Not done yet

- **No tests.** The scaffold's vitest setup is present but nothing is written against it.
  The highest-value targets are `safeReturnTo()`, the single-flight refresh, and
  `parseError()`.
- **`environment.ts` has an empty `apiBase`**, which assumes a production deployment
  serves the API from the same origin behind a reverse proxy. Set it, or set up the
  proxy, before a production build.
- **No i18n.** All copy is inline English.
