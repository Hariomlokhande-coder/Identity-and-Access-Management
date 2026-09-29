package com.example.iam.client;

import java.util.Optional;
import java.util.UUID;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;
import org.springframework.data.jpa.repository.JpaRepository;

public interface ClientApplicationRepository extends JpaRepository<ClientApplication, UUID> {

    Optional<ClientApplication> findByClientId(String clientId);

    boolean existsByClientId(String clientId);

    Page<ClientApplication> findAllByOrderByCreatedAtDesc(Pageable pageable);
}