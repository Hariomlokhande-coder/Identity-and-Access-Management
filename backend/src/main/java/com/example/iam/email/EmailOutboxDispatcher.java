package com.example.iam.email;

import com.example.iam.config.IamProperties;
import java.time.Duration;
import java.time.Instant;
import java.util.List;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.data.domain.PageRequest;
import org.springframework.mail.MailException;
import org.springframework.mail.SimpleMailMessage;
import org.springframework.mail.javamail.JavaMailSender;
import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.stereotype.Component;
import org.springframework.transaction.annotation.Transactional;

/** Drains the outbox with capped exponential backoff. */
@Component
public class EmailOutboxDispatcher {

    private static final Logger log = LoggerFactory.getLogger(EmailOutboxDispatcher.class);
    private static final Duration BASE_BACKOFF = Duration.ofSeconds(30);
    private static final Duration MAX_BACKOFF = Duration.ofHours(1);
    private static final int MAX_ERROR_LENGTH = 512;

    private final EmailOutboxRepository outbox;
    private final JavaMailSender mailSender;
    private final IamProperties properties;

    public EmailOutboxDispatcher(EmailOutboxRepository outbox, JavaMailSender mailSender,
                                 IamProperties properties) {
        this.outbox = outbox;
        this.mailSender = mailSender;
        this.properties = properties;
    }

    @Scheduled(fixedDelayString = "${iam.email.outbox.dispatch-interval:PT10S}")
    @Transactional
    public void dispatchPending() {
        int batchSize = properties.getEmail().getOutbox().getBatchSize();
        List<EmailOutboxEntry> batch = outbox.claimBatch(Instant.now(), PageRequest.of(0, batchSize));
        for (EmailOutboxEntry entry : batch) {
            send(entry);
        }
    }

    private void send(EmailOutboxEntry entry) {
        entry.setAttempts(entry.getAttempts() + 1);
        try {
            SimpleMailMessage message = new SimpleMailMessage();
            message.setFrom(properties.getEmail().getFrom());
            message.setTo(entry.getRecipient());
            message.setSubject(entry.getSubject());
            message.setText(entry.getBody());
            mailSender.send(message);

            entry.setStatus(EmailStatus.SENT);
            entry.setSentAt(Instant.now());
            entry.setLastError(null);
        } catch (MailException e) {
            // The recipient address is logged; the body never is, because reset and
            // verification links are credentials.
            log.warn("Mail delivery attempt {} failed for {}", entry.getAttempts(), entry.getRecipient(), e);
            entry.setLastError(truncate(e.getMessage()));
            if (entry.getAttempts() >= properties.getEmail().getOutbox().getMaxAttempts()) {
                entry.setStatus(EmailStatus.FAILED);
            } else {
                entry.setNextAttemptAt(Instant.now().plus(backoffFor(entry.getAttempts())));
            }
        }
    }

    private Duration backoffFor(int attempts) {
        Duration backoff = BASE_BACKOFF.multipliedBy(1L << Math.min(attempts - 1, 10));
        return backoff.compareTo(MAX_BACKOFF) > 0 ? MAX_BACKOFF : backoff;
    }

    private String truncate(String message) {
        if (message == null) {
            return null;
        }
        return message.length() <= MAX_ERROR_LENGTH ? message : message.substring(0, MAX_ERROR_LENGTH);
    }
}