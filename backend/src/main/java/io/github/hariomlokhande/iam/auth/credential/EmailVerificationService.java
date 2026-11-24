package io.github.hariomlokhande.iam.auth.credential;

import io.github.hariomlokhande.iam.common.Hashing;
import io.github.hariomlokhande.iam.common.SecureTokens;
import io.github.hariomlokhande.iam.config.IamProperties;
import io.github.hariomlokhande.iam.email.MailService;
import io.github.hariomlokhande.iam.user.User;
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