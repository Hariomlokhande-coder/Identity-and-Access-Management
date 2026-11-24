package com.iamplatform.maintenance;

import com.iamplatform.auth.credential.EmailVerificationTokenRepository;
import com.iamplatform.auth.credential.PasswordResetTokenRepository;
import com.iamplatform.auth.token.RefreshTokenRepository;
import com.iamplatform.config.IamProperties;
import com.iamplatform.email.EmailOutboxRepository;
import com.iamplatform.security.LoginAttemptRepository;
import com.iamplatform.session.SessionRepository;
import java.time.Instant;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.stereotype.Component;
import org.springframework.transaction.annotation.Transactional;

/**
 * Removes state that has outlived its purpose.
 *
 * <p>Rows are kept for a grace period past expiry rather than deleted the moment they
 * lapse. Deleting a spent refresh token immediately would erase the evidence that
 * makes reuse detectable: a replayed token has to be recognisable as revoked, not
 * merely unknown.
 *
 * <p>Every instance runs this. The deletes are idempotent range deletes, so a second
 * instance finding nothing to remove is the normal case, not a conflict.
 */
@Component
public class ExpiredDataCleanupJob {

    private static final Logger log = LoggerFactory.getLogger(ExpiredDataCleanupJob.class);

    private final RefreshTokenRepository refreshTokens;
    private final EmailVerificationTokenRepository verificationTokens;
    private final PasswordResetTokenRepository resetTokens;
    private final SessionRepository sessions;
    private final LoginAttemptRepository loginAttempts;
    private final EmailOutboxRepository outbox;
    private final IamProperties properties;

    public ExpiredDataCleanupJob(RefreshTokenRepository refreshTokens,
            EmailVerificationTokenRepository verificationTokens, PasswordResetTokenRepository resetTokens,
            SessionRepository sessions, LoginAttemptRepository loginAttempts, EmailOutboxRepository outbox,
            IamProperties properties) {
        this.refreshTokens = refreshTokens;
        this.verificationTokens = verificationTokens;
        this.resetTokens = resetTokens;
        this.sessions = sessions;
        this.loginAttempts = loginAttempts;
        this.outbox = outbox;
        this.properties = properties;
    }

    @Scheduled(cron = "${iam.cleanup.cron:0 15 3 * * *}")
    @Transactional
    public void purgeExpired() {
        Instant cutoff = Instant.now().minus(properties.getCleanup().getRetention());

        int tokens = refreshTokens.deleteExpiredBefore(cutoff);
        int verifications = verificationTokens.deleteExpiredBefore(cutoff);
        int resets = resetTokens.deleteExpiredBefore(cutoff);
        int staleSessions = sessions.deleteExpiredBefore(cutoff);
        int sentMail = outbox.deleteSentBefore(cutoff);
        // Attempt history is kept far longer than the rest: it is the record an incident
        // investigation reads, and it holds no credential.
        int attempts = loginAttempts.deleteOlderThan(Instant.now().minus(properties.getCleanup().getRetention()
                .multipliedBy(12)));

        log.info("Cleanup removed {} refresh token(s), {} verification token(s), {} reset token(s), "
                        + "{} session(s), {} sent mail row(s) and {} login attempt(s)",
                tokens, verifications, resets, staleSessions, sentMail, attempts);
    }
}
