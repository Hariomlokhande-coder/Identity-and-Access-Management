package com.example.iam.role;

import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.GeneratedValue;
import jakarta.persistence.Id;
import jakarta.persistence.Table;
import java.time.Instant;
import java.util.UUID;
import lombok.Getter;
import lombok.Setter;
import org.hibernate.annotations.CreationTimestamp;

/** A fine-grained capability such as USER_READ. */
@Entity
@Table(name = "permissions")
@Getter
@Setter
public class Permission {

    @Id
    @GeneratedValue
    private UUID id;

    @Column(nullable = false, updatable = false)
    private String name;

    private String description;

    @CreationTimestamp
    @Column(name = "created_at", nullable = false, updatable = false)
    private Instant createdAt;
}