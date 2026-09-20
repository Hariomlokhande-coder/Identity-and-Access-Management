package com.example.iam.common;

import java.util.List;
import org.springframework.data.domain.Page;

/** Stable pagination envelope, so the API never leaks Spring's Page serialization. */
public record PageResponse<T>(
        List<T> items,
        int page,
        int size,
        long totalElements,
        int totalPages) {

    public static <T> PageResponse<T> of(Page<T> page) {
        return new PageResponse<>(
                page.getContent(),
                page.getNumber(),
                page.getSize(),
                page.getTotalElements(),
                page.getTotalPages());
    }
}
