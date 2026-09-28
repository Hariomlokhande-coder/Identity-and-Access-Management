package com.example.iam.client;

import jakarta.persistence.CollectionTable;
import jakarta.persistence.Column;
import jakarta.persistence.ElementCollection;
import jakarta.persistence.Entity;
import jakarta.persistence.EnumType;
import jakarta.persistence.Enumerated;
import jakarta.persistence.FetchType;
import jakarta.persistence.GeneratedValue;
import jakarta.persistence.Id;
import jakarta.persistence.JoinColumn;
import jakarta.persistence.Table;
import jakarta.persistence.Version;
import java.time.Duration;
import java.time.Instant;
import java.util.LinkedHashSet;
import java.util.Set;
import java.util.UUID;
import lombok.Getter;
import lombok.Setter;
import org.hibernate.annotations.CreationTimestamp;
import org.hibernate.annotations.UpdateTimestamp;

/** An application that delegates identity to this platform. */
@Entity
@Table(name = "client_applications")
@Getter
@Setter
public class ClientApplication {

    @Id
    @GeneratedValue
    private UUID id;

    /** Public identifier used in OAuth2 requests and as the token audience. */
    @Column(name = "client_id", nullable = false, updatable = false)
    private String clientId;

    /** BCrypt hash; the raw secret is shown exactly once, at registration. */
    @Column(name = "client_secret_hash")
    private String clientSecretHash;

    @Column(nullable = false)
    private String name;

    @Enumerated(EnumType.STRING)
    @Column(name = "client_type", nullable = false)
    private ClientType clientType = ClientType.CONFIDENTIAL;

    @Enumerated(EnumType.STRING)
    @Column(nullable = false)
    private ClientStatus status = ClientStatus.ACTIVE;

    @Column(name = "require_consent", nullable = false)
    private boolean requireConsent = true;

    @Column(name = "require_pkce", nullable = false)
    private boolean requirePkce = true;

    /** Per-client override of the platform default; null means the default applies. */
    @Column(name = "access_token_ttl_seconds")
    private Integer accessTokenTtlSeconds;

    @Column(name = "refresh_token_ttl_seconds")
    private Integer refreshTokenTtlSeconds;

    @ElementCollection(fetch = FetchType.EAGER)
    @CollectionTable(
            name = "client_redirect_uris",
            joinColumns = @JoinColumn(name = "client_application_id"))
    @Column(name = "redirect_uri", nullable = false)
    private Set<String> redirectUris = new LinkedHashSet<>();

    @ElementCollection(fetch = FetchType.EAGER)
    @CollectionTable(
            name = "client_scopes",
            joinColumns = @JoinColumn(name = "client_application_id"))
    @Column(name = "scope", nullable = false)
    private Set<String> scopes = new LinkedHashSet<>();

    @CreationTimestamp
    @Column(name = "created_at", nullable = false, updatable = false)
    private Instant createdAt;

    @UpdateTimestamp
    @Column(name = "updated_at", nullable = false)
    private Instant updatedAt;

    @Version
    private long version;

    public boolean isActive() {
        return status == ClientStatus.ACTIVE;
    }

    /**
     * Exact string comparison against the registered set. Prefix or startsWith
     * matching is what turns a redirect URI into an open redirect, so it is never
     * attempted here.
     */
    public boolean allowsRedirectUri(String candidate) {
        return candidate != null && redirectUris.contains(candidate);
    }

    public Duration accessTokenTtlOr(Duration fallback) {
        return accessTokenTtlSeconds == null
                ? fallback
                : Duration.ofSeconds(accessTokenTtlSeconds);
    }

    public Duration refreshTokenTtlOr(Duration fallback) {
        return refreshTokenTtlSeconds == null
                ? fallback
                : Duration.ofSeconds(refreshTokenTtlSeconds);
    }
}