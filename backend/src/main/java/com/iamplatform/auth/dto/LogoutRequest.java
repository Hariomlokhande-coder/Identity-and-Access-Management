package com.iamplatform.auth.dto;

import jakarta.validation.constraints.Size;

/**
 * @param refreshToken the token of the session being ended; optional, because the
 *                     access token already identifies the session
 * @param allDevices   when true every other session of the user is ended too
 */
public record LogoutRequest(
        @Size(max = 200) String refreshToken,
        boolean allDevices) {
}
