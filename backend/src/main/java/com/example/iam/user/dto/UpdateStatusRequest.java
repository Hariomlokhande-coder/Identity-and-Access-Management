package com.example.iam.user.dto;

import com.example.iam.user.UserStatus;
import jakarta.validation.constraints.NotNull;

public record UpdateStatusRequest(@NotNull UserStatus status) {
}
