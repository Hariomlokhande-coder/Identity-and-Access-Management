package com.iamplatform.oauth;

import com.iamplatform.audit.AuditEventType;
import com.iamplatform.audit.AuditService;
import com.iamplatform.client.ClientApplication;
import com.iamplatform.exception.ApiException;
import com.iamplatform.user.User;
import com.iamplatform.user.UserRepository;
import java.time.Instant;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Set;
import java.util.UUID;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

/** Records and reads what each user has allowed each application to ask for. */
@Service
public class ConsentService {

    private final UserConsentRepository consents;
    private final UserRepository users;
    private final AuditService auditService;

    public ConsentService(UserConsentRepository consents, UserRepository users, AuditService auditService) {
        this.consents = consents;
        this.users = users;
        this.auditService = auditService;
    }

    /**
     * True only when a live grant already covers every requested scope. A request that
     * adds even one new scope goes back to the user, so an application cannot quietly
     * broaden what it may do.
     */
    @Transactional(readOnly = true)
    public boolean isCovered(UUID userId, ClientApplication client, Set<String> requestedScopes) {
        return consents.findByUserIdAndClientApplicationId(userId, client.getId())
                .map(consent -> consent.covers(requestedScopes))
                .orElse(false);
    }

    /** Approves the requested scopes, keeping anything the user approved earlier. */
    @Transactional
    public void grant(UUID userId, ClientApplication client, Set<String> scopes, String ipAddress) {
        UserConsent consent = consents.findByUserIdAndClientApplicationId(userId, client.getId())
                .orElseGet(() -> newConsent(userId, client));

        // A revoked grant starts over rather than resurrecting the old scope set.
        Set<String> merged = new LinkedHashSet<>(consent.getRevokedAt() == null ? consent.scopeSet() : Set.of());
        merged.addAll(scopes);
        consent.setScopeSet(merged);
        consent.setRevokedAt(null);
        consent.setGrantedAt(Instant.now());
        consents.save(consent);

        auditService.success(AuditEventType.CONSENT_GRANTED, userId, client.getClientId(), ipAddress,
                "scopes " + String.join(" ", merged));
    }

    @Transactional(readOnly = true)
    public List<UserConsent> listForUser(UUID userId) {
        return consents.findActiveByUser(userId);
    }

    /**
     * Withdraws consent. Existing tokens are not affected here; ending the sessions is
     * the caller's decision, because a user revoking consent usually also wants the
     * application signed out, while an administrator may not.
     */
    @Transactional
    public void revoke(UUID userId, UUID clientApplicationId, String ipAddress) {
        UserConsent consent = consents.findByUserIdAndClientApplicationId(userId, clientApplicationId)
                .orElseThrow(() -> ApiException.notFound("Consent"));
        consent.setRevokedAt(Instant.now());
        consents.save(consent);

        auditService.success(AuditEventType.CONSENT_REVOKED, userId, clientApplicationId.toString(), ipAddress,
                null);
    }

    private UserConsent newConsent(UUID userId, ClientApplication client) {
        User user = users.findById(userId).orElseThrow(() -> ApiException.notFound("User"));
        UserConsent consent = new UserConsent();
        consent.setUser(user);
        consent.setClientApplication(client);
        return consent;
    }
}
