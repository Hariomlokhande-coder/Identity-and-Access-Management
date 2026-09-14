package com.example.iam.exception;

import com.fasterxml.jackson.annotation.JsonInclude;

import java.time.Instant;
import java.util.Map;

@JsonInclude(JsonInclude.Include.NON_EMPTY)
public record ErrorResponse(
        Instant timestamp,
        int status,
        String code,
        String message,
        String path,
        String correlationId,
        Map<String, Object> details
) {

    public static ErrorResponse of(
            ErrorCode code,
            String message,
            String path,
            String correlationId,
            Map<String, Object> details
    ) {
        return new ErrorResponse(
                Instant.now(),
                code.status().value(),
                code.name(),
                message,
                path,
                correlationId,
                details == null ? Map.of() : details
        );
    }
}