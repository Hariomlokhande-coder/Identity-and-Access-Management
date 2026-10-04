package com.example.iam.user;

import java.time.Instant;
import java.util.List;
import java.util.Optional;
import java.util.UUID;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;
import org.springframework.data.jpa.repository.EntityGraph;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Modifying;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;

public interface UserRepository extends JpaRepository<User, UUID> {

    /**
     * Fetches the whole authority graph in one query, including each role's client
     * scope. The scope is not optional here: authorities are resolved in the stateless
     * JWT filter, where a lazy association would have no session to load from.
     */
    @EntityGraph(attributePaths = {"roles", "roles.permissions", "roles.clientApplication"})
    Optional<User> findWithRolesByEmail(String email);

    @EntityGraph(attributePaths = {"roles", "roles.permissions", "roles.clientApplication"})
    Optional<User> findWithRolesById(UUID id);

    Optional<User> findByEmail(String email);

    boolean existsByEmail(String email);

    @Query("""
        SELECT u FROM User u
        WHERE u.deletedAt IS NULL
        AND (:query IS NULL OR LOWER(u.email) LIKE LOWER(CONCAT('%', :query, '%')))
        AND (:status IS NULL OR u.status = :status)
        """)
    Page<User> search(@Param("query") String query, @Param("status") UserStatus status, Pageable pageable);

    /**
     * Reads only the permission version, which the JWT filter needs on every request.
     * Loading the whole aggregate for that check would be wasteful.
     */
    @Query("SELECT u.permissionVersion FROM User u WHERE u.id = :id AND u.deletedAt IS NULL")
    Optional<Integer> findPermissionVersion(@Param("id") UUID id);

    @Modifying(clearAutomatically = true, flushAutomatically = true)
    @Query("UPDATE User u SET u.permissionVersion = u.permissionVersion + 1 WHERE u.id = :id")
    int incrementPermissionVersion(@Param("id") UUID id);

    /** Everyone affected by a change to a role, so their tokens can be retired. */
    @Query("SELECT u.id FROM User u JOIN u.roles r WHERE r.id = :roleId")
    List<UUID> findIdsByRoleId(@Param("roleId") UUID roleId);

    @Modifying
    @Query("UPDATE User u SET u.lockedUntil = :until, u.lockoutStrikes = u.lockoutStrikes + 1 WHERE u.id = :id")
    int applyLock(@Param("id") UUID id, @Param("until") Instant until);

    @Modifying
    @Query("UPDATE User u SET u.lockedUntil = NULL, u.lockoutStrikes = 0 WHERE u.id = :id")
    int clearLock(@Param("id") UUID id);

    long countByStatus(UserStatus status);
}