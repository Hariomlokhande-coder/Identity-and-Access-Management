package io.github.hariomlokhande.iam.auth.credential;

import jakarta.persistence.Entity;
import jakarta.persistence.Table;

@Entity
@Table(name = "email_verification_tokens")
public class EmailVerificationToken extends SingleUseToken {

}