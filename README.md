# IAM Platform

An identity service with a Spring Boot API and an Angular console. It handles sign-in, email verification, password resets, sessions, and OAuth 2.0 / OpenID Connect. The console also lets admins manage users, roles, and client applications and view the audit log.

## Run locally

You need Java 21, Maven, and Docker. From the repository root, run:

```sh
cd backend
docker compose --profile console up -d
mvn spring-boot:run
```

- [IAM console](http://localhost:3001)
- [API docs](http://localhost:8081/swagger-ui.html)
- [Mailpit inbox](http://localhost:8025)

Create an account in the console, then open its verification link in Mailpit before signing in. To create the first admin on an empty database, set `IAM_BOOTSTRAP_ADMIN_EMAIL` and `IAM_BOOTSTRAP_ADMIN_PASSWORD` before starting the backend.

## Repository

- [backend/](backend/) contains the API and database migrations. The API uses PostgreSQL and Redis.
- [frontend/](frontend/) contains the Angular console. See its [README](frontend/README.md) for running Angular directly.

## Tests

Run these from `backend/`:

```sh
mvn test
mvn verify
```

`mvn verify` also runs integration tests using PostgreSQL and Redis containers, so Docker must be running.
