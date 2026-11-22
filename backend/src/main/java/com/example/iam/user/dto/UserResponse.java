package com.example.iam.user.dto;

import com.example.iam.role.Role;
import com.example.iam.user.User;
import com.example.iam.user.UserStatus;
import java.time.Instant;
import java.util.Set;
import java.util.TreeSet;
import java.util.UUID;

/**
 * The user representation the API returns. The password hash, permission version and
 * lockout counters are internal and deliberately absent.
 */
public record UserResponse(
        UUID id,
        String email,
        UserStatus status,
        boolean emailVerified,
        Set<String> roles,
        Instant createdAt,
        Instant lastLoginAt,
        Instant lockedUntil) {

    public static UserResponse from(User user) {
        Set<String> roleNames = new TreeSet<>();
        user.getRoles().stream().map(Role::getName).forEach(roleNames::add);
        return new UserResponse(user.getId(), user.getEmail(), user.getStatus(), user.isEmailVerified(),
                roleNames, user.getCreatedAt(), user.getLastLoginAt(), user.getLockedUntil());
    }
}
