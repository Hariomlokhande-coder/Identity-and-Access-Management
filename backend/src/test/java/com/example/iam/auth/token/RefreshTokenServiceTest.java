package com.example.iam.auth.token;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import com.example.iam.client.ClientApplication;
import com.example.iam.common.Hashing;
import com.example.iam.exception.ApiException;
import com.example.iam.exception.ErrorCode;
import com.example.iam.session.UserSession;
import com.example.iam.user.User;
import java.time.Duration;
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

/**
 * Behaviour of refresh-token rotation, including the two situations that must be
 * indistinguishable from the outside: a genuinely replayed token and the losing half
 * of two concurrent refreshes.
 */
@ExtendWith(MockitoExtension.class)
@MockitoSettings(strictness = Strictness.LENIENT)
class RefreshTokenServiceTest {

    private static final Duration TTL = Duration.ofDays(30);
    private static final String RAW_TOKEN = "raw-refresh-token-value";

    @Mock
    private RefreshTokenRepository repository;

    @Mock
    private RefreshTokenFamilyRevoker familyRevoker;

    private RefreshTokenService service;

    private User user;
    private UserSession session;
    private ClientApplication client;
    private RefreshToken stored;

    @BeforeEach
    void setUp() {
        service = new RefreshTokenService(repository, familyRevoker);

        user = new User();
        user.setId(UUID.randomUUID());

        session = new UserSession();
        session.setId(UUID.randomUUID());
        session.setUser(user);
        session.setExpiresAt(Instant.now().plus(Duration.ofDays(1)));

        client = new ClientApplication();
        client.setId(UUID.randomUUID());
        client.setClientId("shop");

        stored = new RefreshToken();
        stored.setId(UUID.randomUUID());
        stored.setFamilyId(UUID.randomUUID());
        stored.setUser(user);
        stored.setSession(session);
        stored.setClientApplication(client);
        stored.setTokenHash(Hashing.sha256Hex(RAW_TOKEN));
        stored.setExpiresAt(Instant.now().plus(TTL));

        when(repository.findByTokenHash(Hashing.sha256Hex(RAW_TOKEN))).thenReturn(Optional.of(stored));
        when(repository.save(any(RefreshToken.class))).thenAnswer(invocation -> invocation.getArgument(0));
        when(repository.getReferenceById(stored.getId())).thenReturn(stored);
    }

    @Test
    @DisplayName("rotation issues a new token in the same family and revokes the old one")
    void rotatesSuccessfully() {
        when(repository.revokeIfActive(eq(stored.getId()), anyString(), any())).thenReturn(1);

        RefreshTokenService.RotationResult result = service.rotate(RAW_TOKEN, "shop", TTL);

        assertThat(result.rawToken()).isNotBlank().isNotEqualTo(RAW_TOKEN);
        assertThat(result.user()).isSameAs(user);

        ArgumentCaptor<RefreshToken> saved = ArgumentCaptor.forClass(RefreshToken.class);
        verify(repository).save(saved.capture());
        assertThat(saved.getValue().getFamilyId()).isEqualTo(stored.getFamilyId());
        // Only the hash is persisted; the raw value exists only in the response.
        assertThat(saved.getValue().getTokenHash()).isEqualTo(Hashing.sha256Hex(result.rawToken()));
        verify(familyRevoker, never()).revoke(any(), any(), any(), anyString());
    }

    /**
     * The concurrency case from the design doc: two refreshes arrive together, the
     * conditional update lets exactly one through, and the loser is treated as reuse.
     */
    @Test
    @DisplayName("losing the conditional update is treated as reuse and kills the family")
    void concurrentRotationLoserTriggersFamilyRevocation() {
        when(repository.revokeIfActive(eq(stored.getId()), anyString(), any())).thenReturn(0);

        assertThatThrownBy(() -> service.rotate(RAW_TOKEN, "shop", TTL))
                .isInstanceOf(ApiException.class)
                .extracting(e -> ((ApiException) e).code())
                .isEqualTo(ErrorCode.INVALID_REFRESH_TOKEN);

        verify(familyRevoker).revoke(eq(stored.getFamilyId()), eq(session.getId()), eq(user.getId()),
                anyString());
    }

    @Test
    @DisplayName("presenting an already-revoked token kills the family")
    void replayOfRevokedTokenTriggersFamilyRevocation() {
        stored.setRevokedAt(Instant.now().minusSeconds(60));

        assertThatThrownBy(() -> service.rotate(RAW_TOKEN, "shop", TTL))
                .isInstanceOf(ApiException.class);

        verify(familyRevoker).revoke(eq(stored.getFamilyId()), eq(session.getId()), eq(user.getId()),
                anyString());
        verify(repository, never()).save(any(RefreshToken.class));
    }

    /**
     * Expiry is not evidence of compromise, so the family survives and the user simply
     * signs in again.
     */
    @Test
    @DisplayName("an expired token is rejected without destroying the family")
    void expiredTokenDoesNotRevokeFamily() {
        stored.setExpiresAt(Instant.now().minusSeconds(1));

        assertThatThrownBy(() -> service.rotate(RAW_TOKEN, "shop", TTL))
                .isInstanceOf(ApiException.class)
                .hasMessageContaining("expired");

        verify(familyRevoker, never()).revoke(any(), any(), any(), anyString());
    }

    @Test
    @DisplayName("a token belonging to another client cannot be redeemed")
    void rejectsTokenPresentedByADifferentClient() {
        assertThatThrownBy(() -> service.rotate(RAW_TOKEN, "bank", TTL))
                .isInstanceOf(ApiException.class);

        verify(familyRevoker).revoke(eq(stored.getFamilyId()), eq(session.getId()), eq(user.getId()),
                anyString());
    }

    /**
     * Using the wrong endpoint is a mistake, not a theft, so the user does not lose
     * their session over it.
     */
    @Test
    @DisplayName("a client-bound token at the first-party endpoint is refused without ending the session")
    void rejectsClientTokenAtTheFirstPartyEndpoint() {
        assertThatThrownBy(() -> service.rotate(RAW_TOKEN, null, TTL))
                .isInstanceOf(ApiException.class)
                .hasMessageContaining("/oauth2/token");

        verify(familyRevoker, never()).revoke(any(), any(), any(), anyString());
    }

    @Test
    @DisplayName("an unknown token is rejected without revealing anything")
    void rejectsUnknownToken() {
        when(repository.findByTokenHash(anyString())).thenReturn(Optional.empty());

        assertThatThrownBy(() -> service.rotate("does-not-exist", "shop", TTL))
                .isInstanceOf(ApiException.class)
                .extracting(e -> ((ApiException) e).code())
                .isEqualTo(ErrorCode.INVALID_REFRESH_TOKEN);
    }

    @Test
    @DisplayName("a revoked session cannot be refreshed back to life")
    void rejectsRefreshOnRevokedSession() {
        when(repository.revokeIfActive(eq(stored.getId()), anyString(), any())).thenReturn(1);
        session.revoke("logout");

        assertThatThrownBy(() -> service.rotate(RAW_TOKEN, "shop", TTL))
                .isInstanceOf(ApiException.class)
                .hasMessageContaining("session is no longer active");
    }
}
