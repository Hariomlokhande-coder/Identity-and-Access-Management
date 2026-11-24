package com.iamplatform.user.dto;

import com.iamplatform.user.UserStatus;
import jakarta.validation.constraints.NotNull;

public record UpdateStatusRequest(@NotNull UserStatus status) {
}
