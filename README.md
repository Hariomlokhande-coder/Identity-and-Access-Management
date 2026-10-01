# Identity & Access Management (IAM) Platform

A centralized identity and access management service built with **Spring Boot 3 / Java 21**, PostgreSQL and Redis. It is designed to handle users, roles and permissions, sessions, client applications and a security audit trail.

> **Status:** foundation in progress. The database schema, domain model, RBAC seed data and error handling are in place; authentication endpoints are on the roadmap below.

## Tech Stack

| Area | Technology |
|---|---|
| Language / Framework | Java 21, Spring Boot 3.3 |
| Security | Spring Security, OAuth2 JOSE (JWT) |
| Persistence | PostgreSQL 16, Spring Data JPA, Flyway migrations |
| Cache / sessions | Redis 7 |
| Email (dev) | Mailpit |
| API docs | springdoc OpenAPI (Swagger UI) |
| Testing | Testcontainers |

## What's implemented

- **Flyway-managed schema** (`V1__baseline.sql`) with 16 tables: `users`, `client_applications`, `client_redirect_uris`, `client_scopes`, `roles`, `permissions`, `role_permissions`, `user_roles`, `sessions`, `refresh_tokens`, `email_verification_tokens`, `password_reset_tokens`, `user_consents`, `login_attempts`, `audit_events`, `email_outbox`.
- **RBAC seed data** (`V2__seed_rbac.sql`): 12 permissions and 3 baseline roles (`ADMIN`, `MANAGER`, `USER`), idempotent so it is safe to re-run.
- **Domain model**: `User`, `Role`, `Permission`, `ClientApplication` with repositories, status/type enums and email normalization.
- **Cross-cutting concerns**: centralized `GlobalExceptionHandler` with typed `ErrorCode`/`ErrorResponse`, a correlation-ID request filter and a generic `PageResponse`.
- **Profiles**: `dev` and `test` configuration, typed config via `IamProperties`.

## Roadmap

- [ ] Registration and email verification
- [ ] Login with JWT access and refresh tokens
- [ ] Password reset flow
- [ ] Session management and revocation
- [ ] Role/permission and client-application admin APIs
- [ ] Login-attempt throttling and audit trail endpoints
- [ ] Integration tests with Testcontainers

## Getting Started

**Prerequisites:** JDK 21, Maven, Docker

```bash
cd backend

# Start PostgreSQL (port 15432), Redis (6379) and Mailpit (SMTP 1025, UI 8025)
docker compose up -d

# Run the app with the dev profile
mvn spring-boot:run -Dspring-boot.run.profiles=dev
```

Flyway applies the migrations automatically on startup. Emails sent in development can be viewed in the Mailpit UI at http://localhost:8025.

## Project Structure

```
backend/src/main/java/com/example/iam
├── client/      # client applications
├── role/        # roles and permissions
├── user/        # users and status handling
├── exception/   # error codes and global handler
├── common/      # correlation ID filter, paging
└── config/      # typed configuration
```
