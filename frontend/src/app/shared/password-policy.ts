import { AbstractControl, ValidationErrors, ValidatorFn } from '@angular/forms';

/**
 * The server's password policy, mirrored so the user is told what is wrong before
 * a round trip rather than after one.
 *
 * These values track iam.password.* in application.yml. The server checks them
 * again - this copy exists for the error message, not for the decision.
 */
export const PASSWORD_POLICY = {
  minLength: 12,
  maxLength: 128,
  requireUpper: true,
  requireLower: true,
  requireDigit: true,
  requireSymbol: true,
} as const;

export interface PasswordRule {
  label: string;
  satisfied: (value: string) => boolean;
}

export const PASSWORD_RULES: readonly PasswordRule[] = [
  {
    label: `At least ${PASSWORD_POLICY.minLength} characters`,
    satisfied: (value) => value.length >= PASSWORD_POLICY.minLength,
  },
  { label: 'An uppercase letter', satisfied: (value) => /[A-Z]/.test(value) },
  { label: 'A lowercase letter', satisfied: (value) => /[a-z]/.test(value) },
  { label: 'A digit', satisfied: (value) => /[0-9]/.test(value) },
  {
    label: 'A symbol',
    satisfied: (value) => /[^A-Za-z0-9]/.test(value),
  },
];

/** Fails with the list of unmet rules so the form can render them all at once. */
export function passwordPolicyValidator(): ValidatorFn {
  return (control: AbstractControl): ValidationErrors | null => {
    const value = String(control.value ?? '');
    if (!value) {
      return null;
    }
    if (value.length > PASSWORD_POLICY.maxLength) {
      return { passwordPolicy: [`No more than ${PASSWORD_POLICY.maxLength} characters`] };
    }
    const unmet = PASSWORD_RULES.filter((rule) => !rule.satisfied(value)).map((rule) => rule.label);
    return unmet.length ? { passwordPolicy: unmet } : null;
  };
}

/** Cross-field check for the "repeat your password" input. */
export function passwordsMatchValidator(passwordKey: string, confirmKey: string): ValidatorFn {
  return (group: AbstractControl): ValidationErrors | null => {
    const password = group.get(passwordKey)?.value;
    const confirm = group.get(confirmKey)?.value;
    if (!confirm) {
      return null;
    }
    return password === confirm ? null : { passwordsMismatch: true };
  };
}
