package com.example.iam.exception;

import com.example.iam.common.CorrelationIdFilter;
import jakarta.servlet.http.HttpServletRequest;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.RestControllerAdvice;
import org.springframework.web.bind.MethodArgumentNotValidException;

import java.util.LinkedHashMap;
import java.util.Map;

@RestControllerAdvice
public class GlobalExceptionHandler {

    private static final Logger log =
            LoggerFactory.getLogger(GlobalExceptionHandler.class);

    @ExceptionHandler(ApiException.class)
    public ResponseEntity<ErrorResponse> handleApi(
            ApiException ex,
            HttpServletRequest request) {

        return build(
                ex.code(),
                ex.getMessage(),
                request,
                ex.details()
        );
    }

    @ExceptionHandler(MethodArgumentNotValidException.class)
    public ResponseEntity<ErrorResponse> handleBeanValidation(
            MethodArgumentNotValidException ex,
            HttpServletRequest request) {

        Map<String, Object> fields = new LinkedHashMap<>();

        ex.getBindingResult().getFieldErrors()
                .forEach(e ->
                        fields.putIfAbsent(
                                e.getField(),
                                e.getDefaultMessage()
                        )
                );

        return build(
                ErrorCode.VALIDATION_FAILED,
                ErrorCode.VALIDATION_FAILED.defaultMessage(),
                request,
                fields
        );
    }

    @ExceptionHandler(Exception.class)
    public ResponseEntity<ErrorResponse> handleUnexpected(
            Exception ex,
            HttpServletRequest request) {

        log.error("Unhandled exception", ex);

        return build(
                ErrorCode.INTERNAL_ERROR,
                ErrorCode.INTERNAL_ERROR.defaultMessage(),
                request,
                Map.of()
        );
    }

    private ResponseEntity<ErrorResponse> build(
            ErrorCode code,
            String message,
            HttpServletRequest request,
            Map<String, Object> details) {

        ErrorResponse body = ErrorResponse.of(
                code,
                message,
                request.getRequestURI(),
                CorrelationIdFilter.current(),
                details
        );

        return ResponseEntity
                .status(code.status())
                .body(body);
    }
}