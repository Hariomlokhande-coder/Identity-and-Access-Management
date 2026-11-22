package com.example.iam.integration;

import static org.assertj.core.api.Assertions.assertThat;

import com.example.iam.auth.dto.TokenResponse;
import com.example.iam.support.IntegrationTestBase;
import java.util.List;
import java.util.Map;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.http.HttpMethod;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;

/** End to end: register, verify, sign in, refresh, sign out. */
class AuthFlowIT extends IntegrationTestBase {

    @Test
    @DisplayName("the documented happy path works from registration through logout")
    void fullLifecycle() {
        String email = uniqueEmail("lifecycle");
        registerAndVerify(email);

        TokenResponse tokens = login(email);
        assertThat(tokens.accessToken()).isNotBlank();
        assertThat(tokens.refreshToken()).isNotBlank();
        assertThat(tokens.tokenType()).isEqualTo("Bearer");

        ResponseEntity<Map> profile = authorized("/users/me", HttpMethod.GET, tokens.accessToken(), null, Map.class);
        assertThat(profile.getStatusCode()).isEqualTo(HttpStatus.OK);
        assertThat(profile.getBody()).containsEntry("email", email);

        ResponseEntity<TokenResponse> refreshed =
                post("/auth/refresh", Map.of("refreshToken", tokens.refreshToken()), TokenResponse.class);
        assertThat(refreshed.getStatusCode()).isEqualTo(HttpStatus.OK);
        assertThat(refreshed.getBody().refreshToken()).isNotEqualTo(tokens.refreshToken());

        ResponseEntity<Map> logout = authorized("/auth/logout", HttpMethod.POST,
                refreshed.getBody().accessToken(), Map.of("allDevices", false), Map.class);
        assertThat(logout.getStatusCode()).isEqualTo(HttpStatus.OK);

        // The access token is blacklisted for the rest of its life, so logout is real
        // rather than a promise the client is trusted to keep.
        ResponseEntity<Map> afterLogout = authorized("/users/me", HttpMethod.GET,
                refreshed.getBody().accessToken(), null, Map.class);
        assertThat(afterLogout.getStatusCode()).isEqualTo(HttpStatus.UNAUTHORIZED);
    }

    @Test
    @DisplayName("an unverified account cannot sign in")
    void unverifiedAccountCannotSignIn() {
        String email = uniqueEmail("unverified");
        post("/auth/register", Map.of("email", email, "password", PASSWORD));

        ResponseEntity<Map> response = post("/auth/login", Map.of("email", email, "password", PASSWORD));

        assertThat(response.getStatusCode()).isEqualTo(HttpStatus.FORBIDDEN);
        assertThat(response.getBody()).containsEntry("code", "EMAIL_NOT_VERIFIED");
    }

    /**
     * The enumeration guarantee: a wrong password and an address that was never
     * registered must be indistinguishable in status, code and message.
     */
    @Test
    @DisplayName("an unknown address and a wrong password produce identical rejections")
    void loginDoesNotRevealWhetherAnAccountExists() {
        String email = uniqueEmail("known");
        registerAndVerify(email);

        ResponseEntity<Map> wrongPassword = post("/auth/login",
                Map.of("email", email, "password", "Wrong!Passphrase1"));
        ResponseEntity<Map> unknownAccount = post("/auth/login",
                Map.of("email", uniqueEmail("nobody"), "password", "Wrong!Passphrase1"));

        assertThat(wrongPassword.getStatusCode()).isEqualTo(HttpStatus.UNAUTHORIZED);
        assertThat(unknownAccount.getStatusCode()).isEqualTo(wrongPassword.getStatusCode());
        assertThat(unknownAccount.getBody()).containsEntry("code", wrongPassword.getBody().get("code"));
        assertThat(unknownAccount.getBody()).containsEntry("message", wrongPassword.getBody().get("message"));
    }

    @Test
    @DisplayName("registering an existing address answers exactly like registering a new one")
    void registrationDoesNotRevealWhetherAnAccountExists() {
        String email = uniqueEmail("duplicate");
        ResponseEntity<Map> first = post("/auth/register", Map.of("email", email, "password", PASSWORD));
        ResponseEntity<Map> second = post("/auth/register", Map.of("email", email, "password", PASSWORD));

        assertThat(second.getStatusCode()).isEqualTo(first.getStatusCode());
        assertThat(second.getBody()).isEqualTo(first.getBody());
    }

    @Test
    @DisplayName("forgot-password answers the same for a registered and an unregistered address")
    void forgotPasswordDoesNotRevealWhetherAnAccountExists() {
        String email = uniqueEmail("reset");
        registerAndVerify(email);

        ResponseEntity<Map> known = post("/auth/forgot-password", Map.of("email", email));
        ResponseEntity<Map> unknown = post("/auth/forgot-password", Map.of("email", uniqueEmail("ghost")));

        assertThat(unknown.getStatusCode()).isEqualTo(known.getStatusCode());
        assertThat(unknown.getBody()).isEqualTo(known.getBody());
    }

    @Test
    @DisplayName("a reset link works once and signs every device out")
    void passwordResetIsSingleUseAndRevokesSessions() {
        String email = uniqueEmail("resetflow");
        registerAndVerify(email);
        TokenResponse tokens = login(email);

        post("/auth/forgot-password", Map.of("email", email));
        String resetToken = latestMailToken();
        String newPassword = "An0ther!Passphrase";

        ResponseEntity<Map> reset = post("/auth/reset-password",
                Map.of("token", resetToken, "newPassword", newPassword));
        assertThat(reset.getStatusCode()).isEqualTo(HttpStatus.OK);

        // The session that existed before the reset is gone.
        ResponseEntity<Map> oldSession = authorized("/users/me", HttpMethod.GET, tokens.accessToken(), null,
                Map.class);
        assertThat(oldSession.getStatusCode()).isEqualTo(HttpStatus.UNAUTHORIZED);

        // The same link cannot be replayed.
        ResponseEntity<Map> replay = post("/auth/reset-password",
                Map.of("token", resetToken, "newPassword", "Third!Passphrase1"));
        assertThat(replay.getStatusCode()).isEqualTo(HttpStatus.UNAUTHORIZED);

        ResponseEntity<TokenResponse> signIn = post("/auth/login",
                Map.of("email", email, "password", newPassword), TokenResponse.class);
        assertThat(signIn.getStatusCode()).isEqualTo(HttpStatus.OK);
    }

    @Test
    @DisplayName("a verification link cannot be used twice")
    void verificationLinkIsSingleUse() {
        String email = uniqueEmail("verifyonce");
        post("/auth/register", Map.of("email", email, "password", PASSWORD));
        String token = latestMailToken();

        assertThat(post("/auth/verify-email", Map.of("token", token)).getStatusCode()).isEqualTo(HttpStatus.OK);
        assertThat(post("/auth/verify-email", Map.of("token", token)).getStatusCode())
                .isEqualTo(HttpStatus.UNAUTHORIZED);
    }

    @Test
    @DisplayName("requesting a new verification link invalidates the previous one")
    void resendSupersedesTheEarlierLink() {
        String email = uniqueEmail("resend");
        post("/auth/register", Map.of("email", email, "password", PASSWORD));
        String firstToken = latestMailToken();

        post("/auth/resend-verification", Map.of("email", email));
        String secondToken = latestMailToken();
        assertThat(secondToken).isNotEqualTo(firstToken);

        assertThat(post("/auth/verify-email", Map.of("token", firstToken)).getStatusCode())
                .isEqualTo(HttpStatus.UNAUTHORIZED);
        assertThat(post("/auth/verify-email", Map.of("token", secondToken)).getStatusCode())
                .isEqualTo(HttpStatus.OK);
    }

    @Test
    @DisplayName("a weak password is rejected with the specific rules it broke")
    void passwordPolicyIsExplicit() {
        ResponseEntity<Map> response =
                post("/auth/register", Map.of("email", uniqueEmail("weak"), "password", "short"));

        assertThat(response.getStatusCode()).isEqualTo(HttpStatus.BAD_REQUEST);
        assertThat(response.getBody()).containsEntry("code", "PASSWORD_POLICY_VIOLATION");
        assertThat((List<?>) ((Map<?, ?>) response.getBody().get("details")).get("violations")).isNotEmpty();
    }

    @Test
    @DisplayName("an unauthenticated call is 401 and an unauthorized one is 403")
    void distinguishesAuthenticationFromAuthorization() {
        String email = uniqueEmail("rbac");
        registerAndVerify(email);
        TokenResponse tokens = login(email);

        assertThat(rest.getForEntity("/users", Map.class).getStatusCode()).isEqualTo(HttpStatus.UNAUTHORIZED);
        // Signed in, but a plain USER holds no USER_READ permission.
        assertThat(authorized("/users", HttpMethod.GET, tokens.accessToken(), null, Map.class).getStatusCode())
                .isEqualTo(HttpStatus.FORBIDDEN);
    }

    @Test
    @DisplayName("a garbage bearer token is rejected without touching the database")
    void rejectsMalformedToken() {
        ResponseEntity<Map> response =
                authorized("/users/me", HttpMethod.GET, "not-a-jwt", null, Map.class);

        assertThat(response.getStatusCode()).isEqualTo(HttpStatus.UNAUTHORIZED);
        assertThat(response.getBody()).containsEntry("code", "INVALID_TOKEN");
    }

    @Test
    @DisplayName("signing out of other devices keeps the current session alive")
    void revokesOtherSessionsOnly() {
        String email = uniqueEmail("multidevice");
        registerAndVerify(email);
        TokenResponse first = login(email);
        TokenResponse second = login(email);

        ResponseEntity<Map> response = authorized("/sessions/all", HttpMethod.DELETE, second.accessToken(), null,
                Map.class);
        assertThat(response.getStatusCode()).isEqualTo(HttpStatus.OK);

        assertThat(authorized("/users/me", HttpMethod.GET, second.accessToken(), null, Map.class).getStatusCode())
                .isEqualTo(HttpStatus.OK);
        assertThat(authorized("/users/me", HttpMethod.GET, first.accessToken(), null, Map.class).getStatusCode())
                .isEqualTo(HttpStatus.UNAUTHORIZED);
    }
}
