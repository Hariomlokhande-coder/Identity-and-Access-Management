package com.example.iam.exception;

import java.util.Map;

public class ApiException extends RuntimeException {

    private final ErrorCode code;
    private final transient Map<String, Object> details;

    public ApiException(ErrorCode code) {
        this(code, code.defaultMessage(), Map.of(), null);
    }

    public ApiException(
            ErrorCode code,
            String message,
            Map<String, Object> details,
            Throwable cause
    ) {
        super(message, cause);
        this.code = code;
        this.details = details == null ? Map.of() : Map.copyOf(details);
    }

    public ErrorCode code() {
        return code;
    }

    public Map<String, Object> details() {
        return details;
    }

    public static ApiException notFound(String resource) {
        return new ApiException(
                ErrorCode.NOT_FOUND,
                resource + " not found",
                Map.of(),
                null
        );
    }

    public static ApiException conflict(String message) {
        return new ApiException(
                ErrorCode.CONFLICT,
                message,
                Map.of(),
                null
        );
    }

    public static ApiException invalid(String message) {
        return new ApiException(
                ErrorCode.INVALID_REQUEST,
                message,
                Map.of(),
                null
        );
    }

    public static ApiException forbidden(String message) {
        return new ApiException(
                ErrorCode.FORBIDDEN,
                message,
                Map.of(),
                null
        );
    }
}