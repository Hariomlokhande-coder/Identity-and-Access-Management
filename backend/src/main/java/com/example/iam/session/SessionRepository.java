package com.example.iam.session;

import java.time.Instant;
import java.util.List;
import java.util.Optional;
import java.util.UUID;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Modifying;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;

public interface SessionRepository extends JpaRepository<UserSession, UUID> {

    @Query("""
            SELECT s FROM UserSession s LEFT JOIN FETCH s.clientApplication
            WHERE s.user.id = :userId AND s.revokedAt IS NULL AND s.expiresAt > :now
            ORDER BY s.lastSeenAt DESC
            """)
    List<UserSession> findActiveByUser(@Param("userId") UUID userId, @Param("now") Instant now);

    @Query("""
            SELECT s FROM UserSession s JOIN FETCH s.user
            WHERE s.ssoTokenHash = :hash AND s.revokedAt IS NULL AND s.expiresAt > :now
            """)
    Optional<UserSession> findActiveBySsoTokenHash(@Param("hash") String hash, @Param("now") Instant now);

    Optional<UserSession> findByIdAndUserId(UUID id, UUID userId);

    long countByUserIdAndRevokedAtIsNull(UUID userId);

    @Modifying(clearAutomatically = true)
    @Query("""
            UPDATE UserSession s SET s.revokedAt = :now, s.revokedReason = :reason
            WHERE s.user.id = :userId AND s.revokedAt IS NULL
            """)
    int revokeAllForUser(@Param("userId") UUID userId, @Param("reason") String reason,
            @Param("now") Instant now);

    @Modifying(clearAutomatically = true)
    @Query("""
            UPDATE UserSession s SET s.revokedAt = :now, s.revokedReason = :reason
            WHERE s.user.id = :userId AND s.revokedAt IS NULL AND s.id <> :exceptId
            """)
    int revokeAllForUserExcept(@Param("userId") UUID userId, @Param("exceptId") UUID exceptId,
            @Param("reason") String reason, @Param("now") Instant now);

    @Modifying
    @Query("UPDATE UserSession s SET s.lastSeenAt = :now WHERE s.id = :id")
    int touch(@Param("id") UUID id, @Param("now") Instant now);

    @Modifying
    @Query("DELETE FROM UserSession s WHERE s.expiresAt < :cutoff")
    int deleteExpiredBefore(@Param("cutoff") Instant cutoff);
}
