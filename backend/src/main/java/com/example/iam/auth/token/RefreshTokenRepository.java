package com.example.iam.auth.token;

import java.time.Instant;
import java.util.Optional;
import java.util.UUID;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Modifying;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;

public interface RefreshTokenRepository extends JpaRepository<RefreshToken, UUID> {

    @Query("""
            SELECT t FROM RefreshToken t
            JOIN FETCH t.user u
            JOIN FETCH t.session s
            LEFT JOIN FETCH t.clientApplication
            WHERE t.tokenHash = :tokenHash
            """)
    Optional<RefreshToken> findByTokenHash(@Param("tokenHash") String tokenHash);

    /**
     * The heart of rotation safety. Two concurrent refreshes with the same token both
     * reach this statement; PostgreSQL serialises them on the row, so exactly one sees
     * revoked_at IS NULL and gets 1 row updated. The caller that gets 0 knows the token
     * was already spent and must treat it as reuse - no distributed lock required.
     */
    @Modifying(clearAutomatically = true, flushAutomatically = true)
    @Query("""
            UPDATE RefreshToken t SET t.revokedAt = :now, t.revokedReason = :reason
            WHERE t.id = :id AND t.revokedAt IS NULL
            """)
    int revokeIfActive(@Param("id") UUID id, @Param("reason") String reason, @Param("now") Instant now);

    @Modifying(clearAutomatically = true)
    @Query("""
            UPDATE RefreshToken t SET t.revokedAt = :now, t.revokedReason = :reason
            WHERE t.familyId = :familyId AND t.revokedAt IS NULL
            """)
    int revokeFamily(@Param("familyId") UUID familyId, @Param("reason") String reason, @Param("now") Instant now);

    @Modifying(clearAutomatically = true)
    @Query("""
            UPDATE RefreshToken t SET t.revokedAt = :now, t.revokedReason = :reason
            WHERE t.session.id = :sessionId AND t.revokedAt IS NULL
            """)
    int revokeBySession(@Param("sessionId") UUID sessionId, @Param("reason") String reason,
            @Param("now") Instant now);

    @Modifying(clearAutomatically = true)
    @Query("""
            UPDATE RefreshToken t SET t.revokedAt = :now, t.revokedReason = :reason
            WHERE t.user.id = :userId AND t.revokedAt IS NULL
            """)
    int revokeAllForUser(@Param("userId") UUID userId, @Param("reason") String reason, @Param("now") Instant now);

    /**
     * Used when one session is deliberately spared. Its refresh token has to survive
     * too, otherwise "sign out my other devices" would quietly break the device the
     * user is holding as soon as its access token expired.
     */
    @Modifying(clearAutomatically = true)
    @Query("""
            UPDATE RefreshToken t SET t.revokedAt = :now, t.revokedReason = :reason
            WHERE t.user.id = :userId AND t.revokedAt IS NULL AND t.session.id <> :exceptSessionId
            """)
    int revokeAllForUserExceptSession(@Param("userId") UUID userId,
            @Param("exceptSessionId") UUID exceptSessionId, @Param("reason") String reason,
            @Param("now") Instant now);

    @Modifying
    @Query("DELETE FROM RefreshToken t WHERE t.expiresAt < :cutoff")
    int deleteExpiredBefore(@Param("cutoff") Instant cutoff);
}
