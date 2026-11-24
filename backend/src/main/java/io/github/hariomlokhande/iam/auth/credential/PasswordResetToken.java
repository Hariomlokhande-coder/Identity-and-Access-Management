package io.github.hariomlokhande.iam.auth.credential;

import jakarta.persistence.Entity;
import jakarta.persistence.Table;

@Entity
@Table(name = "password_reset_tokens")
public class PasswordResetToken extends SingleUseToken {
}
