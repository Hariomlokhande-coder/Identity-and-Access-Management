package io.github.hariomlokhande.iam.user.dto;

import io.github.hariomlokhande.iam.user.UserStatus;
import jakarta.validation.constraints.NotNull;

public record UpdateStatusRequest(@NotNull UserStatus status) {
}
