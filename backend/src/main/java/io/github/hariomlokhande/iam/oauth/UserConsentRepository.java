package io.github.hariomlokhande.iam.oauth;

import java.util.List;
import java.util.Optional;
import java.util.UUID;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;

public interface UserConsentRepository extends JpaRepository<UserConsent, UUID> {

    Optional<UserConsent> findByUserIdAndClientApplicationId(UUID userId, UUID clientApplicationId);

    @Query("""
            SELECT c FROM UserConsent c JOIN FETCH c.clientApplication
            WHERE c.user.id = :userId AND c.revokedAt IS NULL
            """)
    List<UserConsent> findActiveByUser(@Param("userId") UUID userId);
}
