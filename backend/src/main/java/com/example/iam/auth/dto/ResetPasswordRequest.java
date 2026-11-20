package com.example.iam.auth.dto;

import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Size;

public record ResetPasswordRequest(
        @NotBlank @Size(max = 200) String token,
        @NotBlank @Size(max = 200) String newPassword) {
}
