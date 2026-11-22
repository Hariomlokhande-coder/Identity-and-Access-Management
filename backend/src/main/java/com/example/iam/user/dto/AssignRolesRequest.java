package com.example.iam.user.dto;

import jakarta.validation.constraints.NotNull;
import java.util.Set;
import java.util.UUID;

/** Replaces the full set of roles, so a removal is expressed by omission. */
public record AssignRolesRequest(@NotNull Set<UUID> roleIds) {
}
