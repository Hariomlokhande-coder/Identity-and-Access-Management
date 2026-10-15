package com.example.iam.auth;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import com.example.iam.audit.AuditService;
import com.example.iam.auth.credential.EmailVerificationService;
import com.example.iam.auth.credential.EmailVerificationToken;
import com.example.iam.auth.credential.EmailVerificationTokenRepository;
import com.example.iam.auth.dto.MessageResponse;
import com.example.iam.auth.dto.RegisterRequest;
import com.example.iam.common.RequestMetadata;
import com.example.iam.config.IamProperties;
import com.example.iam.exception.ApiException;
import com.example.iam.role.RoleRepository;
import com.example.iam.support.TestProperties;
import com.example.iam.user.User;
import com.example.iam.user.UserRepository;
import com.example.iam.user.UserStatus;
import java.time.Instant;
import java.util.Optional;
import java.util.UUID;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.ArgumentCaptor;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.mockito.junit.jupiter.MockitoSettings;
import org.mockito.quality.Strictness;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;

@ExtendWith(MockitoExtension.class)
@MockitoSettings(strictness = Strictness.LENIENT)
class RegistrationServiceTest {

    private static final RequestMetadata METADATA =
            new RequestMetadata("203.0.113.9", "junit");
    private static final String PASSWORD = "Str0ng!Passphrase";

    @Mock
    private UserRepository users;

    @Mock
    private RoleRepository roles;

    @Mock
    private EmailVerificationTokenRepository verificationTokens;

    @Mock
    private EmailVerificationService verificationService;

    @Mock
    private AuditService auditService;

    private RegistrationService service;

    @BeforeEach
    void setUp() {
        IamProperties properties = TestProperties.create();
        PasswordService passwordService =
                new PasswordService(new BCryptPasswordEncoder(4), properties);

        service = new RegistrationService(
                users, roles, verificationTokens, verificationService,
                passwordService, auditService);

        when(users.saveAndFlush(any(User.class))).thenAnswer(invocation -> {
            User user = invocation.getArgument(0);
            user.setId(UUID.randomUUID());
            return user;
        });

        when(roles.findPlatformRoleByName("USER")).thenReturn(Optional.empty());
    }

    @Test
    @DisplayName("a new registration creates a pending user and sends a verification link")
    void registersNewUser() {
        when(users.findByEmail("new@example.com")).thenReturn(Optional.empty());

        MessageResponse response = service.register(
                new RegisterRequest("New@Example.com ", PASSWORD), METADATA);

        ArgumentCaptor<User> saved = ArgumentCaptor.forClass(User.class);
        verify(users).saveAndFlush(saved.capture());

        assertThat(saved.getValue().getEmail()).isEqualTo("new@example.com");
        assertThat(saved.getValue().getStatus()).isEqualTo(UserStatus.PENDING_VERIFICATION);
        assertThat(saved.getValue().getPasswordHash()).isNotEqualTo(PASSWORD);
        verify(verificationService).issue(saved.getValue());
        assertThat(response.message()).contains("If this email address");
    }

    @Test
    @DisplayName("registering an address that already exists returns the identical response")
    void doesNotRevealExistingAccount() {
        User existing = activeUser("taken@example.com");
        when(users.findByEmail("taken@example.com")).thenReturn(Optional.of(existing));

        MessageResponse duplicate = service.register(
                new RegisterRequest("taken@example.com", PASSWORD), METADATA);

        when(users.findByEmail("fresh@example.com")).thenReturn(Optional.empty());
        MessageResponse fresh = service.register(
                new RegisterRequest("fresh@example.com", PASSWORD), METADATA);

        assertThat(duplicate).isEqualTo(fresh);
        verify(verificationService, never()).issue(existing);
    }

    @Test
    @DisplayName("re-registering an unverified address resends the link instead of duplicating the account")
    void resendsVerificationForPendingAccount() {
        User pending = pendingUser("pending@example.com");
        when(users.findByEmail("pending@example.com")).thenReturn(Optional.of(pending));

        service.register(new RegisterRequest("pending@example.com", PASSWORD), METADATA);

        verify(verificationService).issue(pending);
        verify(users, never()).saveAndFlush(any(User.class));
    }

    @Test
    @DisplayName("a weak password is rejected before the address is even looked up")
    void validatesPasswordBeforeLookup() {
        assertThatThrownBy(() -> service.register(
                new RegisterRequest("new@example.com", "weak"), METADATA))
                .isInstanceOf(ApiException.class);

        verify(users, never()).findByEmail(anyString());
    }

    @Test
    @DisplayName("a verification link that loses the single-use race is rejected")
    void rejectsAlreadyConsumedVerificationToken() {
        EmailVerificationToken token = tokenFor(activeUser("someone@example.com"));
        when(verificationTokens.findByTokenHash(anyString())).thenReturn(Optional.of(token));
        when(verificationTokens.markUsed(eq(token.getId()), any())).thenReturn(0);

        assertThatThrownBy(() -> service.verifyEmail("raw-token", METADATA))
                .isInstanceOf(ApiException.class)
                .hasMessageContaining("invalid, expired or already used");
    }

    @Test
    @DisplayName("an unknown verification link produces the same message as a used one")
    void unknownAndUsedTokensLookIdentical() {
        when(verificationTokens.findByTokenHash(anyString())).thenReturn(Optional.empty());

        assertThatThrownBy(() -> service.verifyEmail("nonsense", METADATA))
                .isInstanceOf(ApiException.class)
                .hasMessageContaining("invalid, expired or already used");
    }

    @Test
    @DisplayName("verifying activates the account")
    void verificationActivatesAccount() {
        User user = pendingUser("someone@example.com");
        EmailVerificationToken token = tokenFor(user);
        when(verificationTokens.findByTokenHash(anyString())).thenReturn(Optional.of(token));
        when(verificationTokens.markUsed(eq(token.getId()), any())).thenReturn(1);
        when(users.findById(user.getId())).thenReturn(Optional.of(user));

        service.verifyEmail("raw-token", METADATA);

        assertThat(user.isEmailVerified()).isTrue();
        assertThat(user.getStatus()).isEqualTo(UserStatus.ACTIVE);
    }

    @Test
    @DisplayName("resend answers the same for a known and an unknown address")
    void resendDoesNotRevealExistence() {
        when(users.findByEmail("nobody@example.com")).thenReturn(Optional.empty());

        MessageResponse unknown =
                service.resendVerification("nobody@example.com", METADATA);

        User pending = pendingUser("pending@example.com");
        when(users.findByEmail("pending@example.com")).thenReturn(Optional.of(pending));

        MessageResponse known =
                service.resendVerification("pending@example.com", METADATA);

        assertThat(unknown).isEqualTo(known);
        verify(verificationService).issue(pending);
    }

    private EmailVerificationToken tokenFor(User user) {
        EmailVerificationToken token = new EmailVerificationToken();
        token.setId(UUID.randomUUID());
        token.setUser(user);
        token.setExpiresAt(Instant.now().plusSeconds(600));
        return token;
    }

    private User activeUser(String email) {
        User user = new User();
        user.setId(UUID.randomUUID());
        user.setEmail(email);
        user.setEmailVerified(true);
        user.setStatus(UserStatus.ACTIVE);
        return user;
    }

    private User pendingUser(String email) {
        User user = activeUser(email);
        user.setEmailVerified(false);
        user.setStatus(UserStatus.PENDING_VERIFICATION);
        return user;
    }
}