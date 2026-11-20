package com.example.iam.auth.dto;

import jakarta.validation.constraints.Email;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Size;

/** Shared body of the two flows that start from an address alone: forgot password
 * and resend verification. Both answer identically whether or not the address is
 * registered, so they need nothing else. */
public record EmailOnlyRequest(@NotBlank @Email @Size(max = 320) String email) {
}
