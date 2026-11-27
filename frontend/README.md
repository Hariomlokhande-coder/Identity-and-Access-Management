# IAM Console

The Angular frontend for the IAM Platform. It handles sign-in, registration, and OAuth consent. Users can manage their profile and sessions, and admins can manage users, roles, and client applications.

## Run locally

Start the backend using the [root README](../README.md). If you started Docker Compose with the `console` profile, the frontend is already running.

To run Angular directly, use Node.js 22.12 or newer in the 22.x series and run these commands from `frontend/`:

```sh
npm ci --legacy-peer-deps
npm start
```

Open [the console](http://localhost:3001). It calls the API at `http://localhost:8081`. Verification and password reset emails appear in [Mailpit](http://localhost:8025).

## Build

```sh
npm run build
```

The production build goes to `dist/frontend/browser`. It uses the same origin for API requests by default. If the API is hosted separately, set `apiBase` in [environment.ts](src/environments/environment.ts) before building.
