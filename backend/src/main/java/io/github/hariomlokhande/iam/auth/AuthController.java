package io.github.hariomlokhande.iam.auth;

import io.github.hariomlokhande.iam.auth.dto.ChangePasswordRequest;
import io.github.hariomlokhande.iam.auth.dto.EmailOnlyRequest;
import io.github.hariomlokhande.iam.auth.dto.LoginRequest;
import io.github.hariomlokhande.iam.auth.dto.LogoutRequest;
import io.github.hariomlokhande.iam.auth.dto.MessageResponse;
import io.github.hariomlokhande.iam.auth.dto.RefreshRequest;
import io.github.hariomlokhande.iam.auth.dto.RegisterRequest;
import io.github.hariomlokhande.iam.auth.dto.ResetPasswordRequest;
import io.github.hariomlokhande.iam.auth.dto.TokenResponse;
import io.github.hariomlokhande.iam.auth.dto.VerifyEmailRequest;
import io.github.hariomlokhande.iam.common.RequestMetadata;
import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.tags.Tag;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import jakarta.validation.Valid;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

/**
 * The first-party authentication API.
 *
 * <p>Endpoints here are thin on purpose: they translate HTTP into a service call and
 * back. Every security decision - what to reveal, what to record, what to revoke -
 * belongs to the services, so no rule can be accidentally weakened by one controller
 * doing things slightly differently from another.
 */
@RestController
@RequestMapping("/auth")
@Tag(name = "Authentication")
public class AuthController {

    private final RegistrationService registrationService;
    private final AuthenticationService authenticationService;
    private final PasswordResetService passwordResetService;

    public AuthController(RegistrationService registrationService, AuthenticationService authenticationService,
            PasswordResetService passwordResetService) {
        this.registrationService = registrationService;
        this.authenticationService = authenticationService;
        this.passwordResetService = passwordResetService;
    }

    @PostMapping("/register")
    @Operation(summary = "Register an account",
            description = "Always answers identically, so it cannot be used to discover which addresses exist.")
    public ResponseEntity<MessageResponse> register(@Valid @RequestBody RegisterRequest request,
            HttpServletRequest httpRequest) {
        MessageResponse response = registrationService.register(request, RequestMetadata.from(httpRequest));
        return ResponseEntity.accepted().body(response);
    }

    @PostMapping("/verify-email")
    @Operation(summary = "Confirm an email address with the token from the verification mail")
    public MessageResponse verifyEmail(@Valid @RequestBody VerifyEmailRequest request,
            HttpServletRequest httpRequest) {
        return registrationService.verifyEmail(request.token(), RequestMetadata.from(httpRequest));
    }

    @PostMapping("/resend-verification")
    @Operation(summary = "Send a fresh verification link, invalidating the previous one")
    public ResponseEntity<MessageResponse> resendVerification(@Valid @RequestBody EmailOnlyRequest request,
            HttpServletRequest httpRequest) {
        MessageResponse response =
                registrationService.resendVerification(request.email(), RequestMetadata.from(httpRequest));
        return ResponseEntity.accepted().body(response);
    }

    @PostMapping("/login")
    @Operation(summary = "Sign in and receive an access and refresh token")
    public TokenResponse login(@Valid @RequestBody LoginRequest request, HttpServletRequest httpRequest,
            HttpServletResponse httpResponse) {
        return authenticationService.login(request, RequestMetadata.from(httpRequest), httpResponse);
    }

    @PostMapping("/refresh")
    @Operation(summary = "Exchange a refresh token for a new token pair",
            description = "The presented token is rotated out; presenting it twice revokes the whole family.")
    public TokenResponse refresh(@Valid @RequestBody RefreshRequest request, HttpServletRequest httpRequest) {
        return authenticationService.refresh(request, RequestMetadata.from(httpRequest));
    }

    @PostMapping("/logout")
    @Operation(summary = "End the current session, or every session of the user")
    public MessageResponse logout(@RequestBody(required = false) LogoutRequest request,
            HttpServletRequest httpRequest, HttpServletResponse httpResponse) {
        return authenticationService.logout(request, RequestMetadata.from(httpRequest), httpResponse);
    }

    @PostMapping("/forgot-password")
    @Operation(summary = "Request a password reset link",
            description = "Answers the same whether or not the address is registered.")
    public ResponseEntity<MessageResponse> forgotPassword(@Valid @RequestBody EmailOnlyRequest request,
            HttpServletRequest httpRequest) {
        MessageResponse response =
                passwordResetService.requestReset(request.email(), RequestMetadata.from(httpRequest));
        return ResponseEntity.accepted().body(response);
    }

    @PostMapping("/reset-password")
    @Operation(summary = "Set a new password using a reset link",
            description = "Revokes every session of the account.")
    public MessageResponse resetPassword(@Valid @RequestBody ResetPasswordRequest request,
            HttpServletRequest httpRequest) {
        return passwordResetService.resetPassword(request.token(), request.newPassword(),
                RequestMetadata.from(httpRequest));
    }

    @PostMapping("/change-password")
    @Operation(summary = "Change the password of the signed-in user")
    public MessageResponse changePassword(@Valid @RequestBody ChangePasswordRequest request,
            HttpServletRequest httpRequest) {
        return passwordResetService.changePassword(request.currentPassword(), request.newPassword(),
                RequestMetadata.from(httpRequest));
    }
}
