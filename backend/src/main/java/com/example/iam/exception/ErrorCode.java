package com.example.iam.exception;

import org.springframework.http.HttpStatus;

public enum ErrorCode {

    VALIDATION_FAILED(HttpStatus.BAD_REQUEST, "Request validation failed"),
    INVALID_REQUEST(HttpStatus.BAD_REQUEST, "The request is invalid"),
    PASSWORD_POLICY_VIOLATION(
            HttpStatus.BAD_REQUEST,
            "Password does not meet the required policy"
    ),

    UNAUTHENTICATED(
            HttpStatus.UNAUTHORIZED,
            "Authentication is required"
    ),
    INVALID_CREDENTIALS(
            HttpStatus.UNAUTHORIZED,
            "Invalid email or password"
    ),
    INVALID_TOKEN(
            HttpStatus.UNAUTHORIZED,
            "The token is invalid"
    ),
    TOKEN_EXPIRED(
            HttpStatus.UNAUTHORIZED,
            "The token has expired"
    ),
    INVALID_REFRESH_TOKEN(
            HttpStatus.UNAUTHORIZED,
            "The refresh token is invalid or has been revoked"
    ),

    FORBIDDEN(
            HttpStatus.FORBIDDEN,
            "You are not allowed to perform this action"
    ),
    ACCOUNT_LOCKED(
            HttpStatus.FORBIDDEN,
            "Account temporarily locked after repeated failed attempts"
    ),
    ACCOUNT_DISABLED(
            HttpStatus.FORBIDDEN,
            "This account is not active"
    ),
    EMAIL_NOT_VERIFIED(
            HttpStatus.FORBIDDEN,
            "Email address must be verified before signing in"
    ),
    CONSENT_REQUIRED(
            HttpStatus.FORBIDDEN,
            "User consent is required"
    ),

    NOT_FOUND(
            HttpStatus.NOT_FOUND,
            "Resource not found"
    ),
    CONFLICT(
            HttpStatus.CONFLICT,
            "The resource conflicts with an existing one"
    ),
    RATE_LIMITED(
            HttpStatus.TOO_MANY_REQUESTS,
            "Too many requests"
    ),

    INTERNAL_ERROR(
            HttpStatus.INTERNAL_SERVER_ERROR,
            "Something went wrong"
    ),
    SERVICE_UNAVAILABLE(
            HttpStatus.SERVICE_UNAVAILABLE,
            "A dependency is unavailable"
    );

    private final HttpStatus status;
    private final String defaultMessage;

    ErrorCode(HttpStatus status, String defaultMessage) {
        this.status = status;
        this.defaultMessage = defaultMessage;
    }

    public HttpStatus status() {
        return status;
    }

    public String defaultMessage() {
        return defaultMessage;
    }
}