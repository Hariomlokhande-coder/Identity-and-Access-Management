package io.github.hariomlokhande.iam.admin;

import io.github.hariomlokhande.iam.auth.PasswordService;
import io.github.hariomlokhande.iam.config.IamProperties;
import io.github.hariomlokhande.iam.role.Role;
import io.github.hariomlokhande.iam.role.RoleRepository;
import io.github.hariomlokhande.iam.user.EmailNormalizer;
import io.github.hariomlokhande.iam.user.User;
import io.github.hariomlokhande.iam.user.UserRepository;
import io.github.hariomlokhande.iam.user.UserStatus;
import java.time.Instant;
import java.util.Optional;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.boot.ApplicationArguments;
import org.springframework.boot.ApplicationRunner;
import org.springframework.stereotype.Component;
import org.springframework.transaction.annotation.Transactional;

/**
 * Creates the first administrator, once, from configuration.
 *
 * <p>A seeded admin with a default password in a migration would be a backdoor in
 * every deployment that forgot to change it. Instead nothing is created unless an
 * operator supplies both an address and a password, and then only while no user exists
 * at all - so this can never quietly resurrect an account that was deliberately
 * removed.
 */
@Component
public class AdminBootstrap implements ApplicationRunner {

    private static final Logger log = LoggerFactory.getLogger(AdminBootstrap.class);
    private static final String ADMIN_ROLE = "ADMIN";

    private final UserRepository users;
    private final RoleRepository roles;
    private final PasswordService passwordService;
    private final IamProperties properties;

    public AdminBootstrap(UserRepository users, RoleRepository roles, PasswordService passwordService,
            IamProperties properties) {
        this.users = users;
        this.roles = roles;
        this.passwordService = passwordService;
        this.properties = properties;
    }

    @Override
    @Transactional
    public void run(ApplicationArguments args) {
        IamProperties.Bootstrap bootstrap = properties.getBootstrap();
        String email = EmailNormalizer.normalize(bootstrap.getAdminEmail());
        String password = bootstrap.getAdminPassword();

        if (email == null || email.isBlank() || password == null || password.isBlank()) {
            return;
        }
        if (users.count() > 0) {
            log.debug("Skipping administrator bootstrap: the platform already has users");
            return;
        }

        passwordService.validate(password, email);
        Optional<Role> adminRole = roles.findPlatformRoleByName(ADMIN_ROLE);
        if (adminRole.isEmpty()) {
            log.error("Cannot bootstrap an administrator: the {} role is missing", ADMIN_ROLE);
            return;
        }

        User admin = new User();
        admin.setEmail(email);
        admin.setPasswordHash(passwordService.hash(password));
        // Verified on purpose: there is no one to approve the verification mail yet.
        admin.setEmailVerified(true);
        admin.setStatus(UserStatus.ACTIVE);
        admin.setPasswordChangedAt(Instant.now());
        admin.getRoles().add(adminRole.get());
        users.save(admin);

        log.warn("Created the bootstrap administrator {}. Sign in, change this password, and remove "
                + "IAM_BOOTSTRAP_ADMIN_PASSWORD from the environment.", email);
    }
}
