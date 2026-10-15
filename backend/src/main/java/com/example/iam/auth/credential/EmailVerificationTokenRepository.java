package com.example.iam.auth.credential;

import java.time.Instant;
import java.util.Optional;
import java.util.UUID;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Modifying;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;

public interface EmailVerificationTokenRepository
        extends JpaRepository<EmailVerificationToken, UUID> {

    @Query("SELECT t FROM EmailVerificationToken t JOIN FETCH t.user WHERE t.tokenHash = :hash")
    Optional<EmailVerificationToken> findByTokenHash(@Param("hash") String hash);

    @Modifying(clearAutomatically = true, flushAutomatically = true)
    @Query("""
            UPDATE EmailVerificationToken t SET t.usedAt = :now
            WHERE t.id = :id AND t.usedAt IS NULL AND t.invalidatedAt IS NULL AND t.expiresAt > :now
            """)
    int markUsed(@Param("id") UUID id, @Param("now") Instant now);

    @Modifying(clearAutomatically = true)
    @Query("""
            UPDATE EmailVerificationToken t SET t.invalidatedAt = :now
            WHERE t.user.id = :userId AND t.usedAt IS NULL AND t.invalidatedAt IS NULL
            """)
    int invalidateActiveForUser(@Param("userId") UUID userId, @Param("now") Instant now);

    @Modifying
    @Query("DELETE FROM EmailVerificationToken t WHERE t.expiresAt < :cutoff")
    int deleteExpiredBefore(@Param("cutoff") Instant cutoff);
}