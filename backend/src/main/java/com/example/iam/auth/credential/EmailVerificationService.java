package com.example.iam.auth.credential;

import com.example.iam.common.Hashing;
import com.example.iam.common.SecureTokens;
import com.example.iam.config.IamProperties;
import com.example.iam.email.MailService;
import com.example.iam.user.User;
import java.time.Instant;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Propagation;
import org.springframework.transaction.annotation.Transactional;

@Service
public class EmailVerificationService {

    private final EmailVerificationTokenRepository tokens;
    private final MailService mailService;
    private final IamProperties properties;

    public EmailVerificationService(
            EmailVerificationTokenRepository tokens,
            MailService mailService,
            IamProperties properties) {
        this.tokens = tokens;
        this.mailService = mailService;
        this.properties = properties;
    }

    @Transactional(propagation = Propagation.MANDATORY)
    public void issue(User user) {
        Instant now = Instant.now();
        tokens.invalidateActiveForUser(user.getId(), now);

        String rawToken = SecureTokens.generate();

        EmailVerificationToken token = new EmailVerificationToken();
        token.setUser(user);
        token.setTokenHash(Hashing.sha256Hex(rawToken));
        token.setExpiresAt(
                now.plus(properties.getToken().getEmailVerificationTtl()));

        tokens.save(token);
        mailService.enqueueVerification(user.getEmail(), rawToken);
    }
}