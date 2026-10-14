package com.example.iam.email;

import com.example.iam.config.IamProperties;
import java.time.Duration;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

/**
 * The only way mail enters the system. Callers enqueue inside their own transaction
 * and return; nothing here touches SMTP.
 */
@Service
public class MailService {

    private final EmailOutboxRepository outbox;
    private final IamProperties properties;

    public MailService(EmailOutboxRepository outbox, IamProperties properties) {
        this.outbox = outbox;
        this.properties = properties;
    }

    @Transactional(propagation = org.springframework.transaction.annotation.Propagation.MANDATORY)
    public void enqueueVerification(String recipient, String rawToken) {
        Duration ttl = properties.getToken().getEmailVerificationTtl();
        String link = properties.getEmail().getVerificationUrlTemplate().formatted(rawToken);
        enqueue(recipient, EmailTemplates.verificationSubject(),
                EmailTemplates.verificationBody(link, ttl.toHours()));
    }

    @Transactional(propagation = org.springframework.transaction.annotation.Propagation.MANDATORY)
    public void enqueuePasswordReset(String recipient, String rawToken) {
        Duration ttl = properties.getToken().getPasswordResetTtl();
        String link = properties.getEmail().getResetUrlTemplate().formatted(rawToken);
        enqueue(recipient, EmailTemplates.passwordResetSubject(),
                EmailTemplates.passwordResetBody(link, ttl.toMinutes()));
    }

    @Transactional(propagation = org.springframework.transaction.annotation.Propagation.MANDATORY)
    public void enqueuePasswordChangedNotice(String recipient) {
        enqueue(recipient, EmailTemplates.passwordChangedSubject(),
                EmailTemplates.passwordChangedBody());
    }

    private void enqueue(String recipient, String subject, String body) {
        EmailOutboxEntry entry = new EmailOutboxEntry();
        entry.setRecipient(recipient);
        entry.setSubject(subject);
        entry.setBody(body);
        outbox.save(entry);
    }
}