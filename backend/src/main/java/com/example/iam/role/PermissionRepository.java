package com.example.iam.role;

import java.util.List;
import java.util.Set;
import java.util.UUID;
import org.springframework.data.jpa.repository.JpaRepository;

public interface PermissionRepository extends JpaRepository<Permission, UUID> {

    List<Permission> findAllByNameIn(Set<String> names);

    List<Permission> findAllByOrderByName();
}