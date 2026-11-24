package com.iamplatform.oauth;

import com.iamplatform.client.ClientApplication;
import com.iamplatform.user.User;
import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.FetchType;
import jakarta.persistence.GeneratedValue;
import jakarta.persistence.Id;
import jakarta.persistence.JoinColumn;
import jakarta.persistence.ManyToOne;
import jakarta.persistence.Table;
import jakarta.persistence.Version;
import java.time.Instant;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Set;
import java.util.UUID;
import lombok.Getter;
import lombok.Setter;

/**
 * What a user has agreed one application may ask for.
 *
 * <p>Consent is recorded per scope, not per application, so widening the request later
 * has to be approved again rather than riding on an old approval.
 */
@Entity
@Table(name = "user_consents")
@Getter
@Setter
public class UserConsent {

    @Id
    @GeneratedValue
    private UUID id;

    @ManyToOne(fetch = FetchType.LAZY, optional = false)
    @JoinColumn(name = "user_id", nullable = false)
    private User user;

    @ManyToOne(fetch = FetchType.LAZY, optional = false)
    @JoinColumn(name = "client_application_id", nullable = false)
    private ClientApplication clientApplication;

    @Column(nullable = false)
    private String scopes;

    @Column(name = "granted_at", nullable = false)
    private Instant grantedAt = Instant.now();

    @Column(name = "revoked_at")
    private Instant revokedAt;

    @Version
    private long version;

    public Set<String> scopeSet() {
        if (scopes == null || scopes.isBlank()) {
            return Set.of();
        }
        return new LinkedHashSet<>(List.of(scopes.trim().split(" ")));
    }

    public void setScopeSet(Set<String> values) {
        this.scopes = String.join(" ", values);
    }

    /** True only when this grant already covers everything being asked for now. */
    public boolean covers(Set<String> requested) {
        return revokedAt == null && scopeSet().containsAll(requested);
    }
}
