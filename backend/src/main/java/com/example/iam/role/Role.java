package com.example.iam.role;

import com.example.iam.client.ClientApplication;
import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.FetchType;
import jakarta.persistence.GeneratedValue;
import jakarta.persistence.Id;
import jakarta.persistence.JoinColumn;
import jakarta.persistence.JoinTable;
import jakarta.persistence.ManyToMany;
import jakarta.persistence.ManyToOne;
import jakarta.persistence.Table;
import jakarta.persistence.Version;
import java.time.Instant;
import java.util.LinkedHashSet;
import java.util.Set;
import java.util.UUID;
import lombok.Getter;
import lombok.Setter;
import org.hibernate.annotations.CreationTimestamp;
import org.hibernate.annotations.UpdateTimestamp;

@Entity
@Table(name = "roles")
@Getter
@Setter
public class Role {

    @Id
    @GeneratedValue
    private UUID id;

    @Column(nullable = false)
    private String name;

    private String description;

    /**
     * Null means the role is platform-wide. Otherwise it only takes effect in tokens
     * issued for that client, which is how cross-application role leakage is avoided.
     */
    @ManyToOne(fetch = FetchType.LAZY)
    @JoinColumn(name = "client_application_id")
    private ClientApplication clientApplication;

    /** Seeded roles cannot be renamed or deleted through the API. */
    @Column(name = "system_role", nullable = false)
    private boolean systemRole;

    @ManyToMany(fetch = FetchType.LAZY)
    @JoinTable(name = "role_permissions",
            joinColumns = @JoinColumn(name = "role_id"),
            inverseJoinColumns = @JoinColumn(name = "permission_id"))
    private Set<Permission> permissions = new LinkedHashSet<>();

    @CreationTimestamp
    @Column(name = "created_at", nullable = false, updatable = false)
    private Instant createdAt;

    @UpdateTimestamp
    @Column(name = "updated_at", nullable = false)
    private Instant updatedAt;

    @Version
    private long version;

    /** A platform role applies everywhere; a scoped role only inside its own client. */
    public boolean appliesTo(String clientId) {
        return clientApplication == null || clientApplication.getClientId().equals(clientId);
    }
}s