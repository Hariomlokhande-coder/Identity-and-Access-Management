package com.example.iam.role;

import java.util.List;
import java.util.Optional;
import java.util.Set;
import java.util.UUID;
import org.springframework.data.jpa.repository.EntityGraph;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;

public interface RoleRepository extends JpaRepository<Role, UUID> {

    @EntityGraph(attributePaths = "permissions")
    Optional<Role> findWithPermissionsById(UUID id);

    @EntityGraph(attributePaths = "permissions")
    List<Role> findAllByIdIn(Set<UUID> ids);

    @EntityGraph(attributePaths = {"permissions", "clientApplication"})
    @Query("SELECT r FROM Role r ORDER BY r.name")
    List<Role> findAllWithPermissions();

    @Query("SELECT r FROM Role r WHERE r.name = :name AND r.clientApplication IS NULL")
    Optional<Role> findPlatformRoleByName(@Param("name") String name);

    @Query("SELECT r FROM Role r WHERE r.name = :name AND r.clientApplication.id = :clientApplicationId")
    Optional<Role> findScopedRoleByName(@Param("name") String name,
                                        @Param("clientApplicationId") UUID clientApplicationId);

    @EntityGraph(attributePaths = "permissions")
    @Query("SELECT r FROM Role r WHERE r.name IN :names AND r.clientApplication IS NULL")
    List<Role> findPlatformRolesByNames(@Param("names") Set<String> names);

    long countByClientApplicationId(UUID clientApplicationId);
}