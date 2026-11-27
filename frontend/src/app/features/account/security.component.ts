import { ChangeDetectionStrategy, Component, computed, inject, signal } from '@angular/core';
import { FormBuilder, ReactiveFormsModule, Validators } from '@angular/forms';
import { AuthApi } from '../../core/api/auth.api';
import { AuthService } from '../../core/auth/auth.service';
import { ParsedError, errorText, parseError } from '../../core/http/api-error';
import { NotificationsService } from '../../core/notifications.service';
import {
  PASSWORD_RULES,
  passwordPolicyValidator,
  passwordsMatchValidator,
} from '../../shared/password-policy';
import { AlertComponent } from '../../shared/ui/alert.component';

/** Changing the password of the account you are signed in as. */
@Component({
  selector: 'app-security',
  changeDetection: ChangeDetectionStrategy.OnPush,
  imports: [ReactiveFormsModule, AlertComponent],
  template: `
    <div class="page-header">
      <div>
        <h1>Security</h1>
        <p class="page-header__subtitle">
          Changing your password does not sign your other devices out. To do that, use
          Devices.
        </p>
      </div>
    </div>

    <section class="card form-card">
      <h2>Change password</h2>

      <form [formGroup]="form" (ngSubmit)="submit()" novalidate>
        <app-alert [text]="errorMessage()" [correlationId]="error()?.correlationId ?? null" />

        <label class="field mt-2">
          <span class="field__label">Current password</span>
          <input type="password" formControlName="currentPassword" autocomplete="current-password" />
          <p class="field__hint">
            Required. Knowing the current password is what stops a borrowed session from
            taking the account over.
          </p>
        </label>

        <label class="field">
          <span class="field__label">New password</span>
          <input type="password" formControlName="newPassword" autocomplete="new-password" />
        </label>

        <ul class="rules">
          @for (rule of rules; track rule.label) {
            <li [class.rules__met]="rule.satisfied(form.controls.newPassword.value)">
              <span aria-hidden="true">{{ rule.satisfied(form.controls.newPassword.value) ? '✓' : '·' }}</span>
              {{ rule.label }}
            </li>
          }
        </ul>

        <label class="field mt-2">
          <span class="field__label">Repeat new password</span>
          <input type="password" formControlName="confirm" autocomplete="new-password" />
          @if (form.hasError('passwordsMismatch') && form.controls.confirm.touched) {
            <p class="field__error">The two passwords do not match.</p>
          }
        </label>

        <button type="submit" class="btn btn--primary" [disabled]="busy()">
          {{ busy() ? 'Saving…' : 'Change password' }}
        </button>
      </form>
    </section>
  `,
  styles: `
    .form-card { max-width: 32rem; }
    .rules {
      list-style: none;
      margin: 0.2rem 0 0;
      padding: 0;
      display: grid;
      gap: 0.15rem;
      font-size: 0.78rem;
      color: var(--fg-muted);
    }
    .rules li { display: flex; gap: 0.45rem; }
    .rules__met { color: var(--ok-fg); }
  `,
})
export class SecurityComponent {
  private readonly fb = inject(FormBuilder);
  private readonly api = inject(AuthApi);
  private readonly auth = inject(AuthService);
  private readonly notifications = inject(NotificationsService);

  protected readonly rules = PASSWORD_RULES;
  protected readonly busy = signal(false);
  protected readonly error = signal<ParsedError | null>(null);
  protected readonly errorMessage = computed(() => {
    const parsed = this.error();
    return parsed ? errorText(parsed) : null;
  });

  protected readonly form = this.fb.nonNullable.group(
    {
      currentPassword: ['', [Validators.required]],
      newPassword: ['', [Validators.required, passwordPolicyValidator()]],
      confirm: ['', [Validators.required]],
    },
    { validators: passwordsMatchValidator('newPassword', 'confirm') },
  );

  protected submit(): void {
    if (this.form.invalid || this.busy()) {
      this.form.markAllAsTouched();
      return;
    }
    this.busy.set(true);
    this.error.set(null);

    const { currentPassword, newPassword } = this.form.getRawValue();
    this.api.changePassword({ currentPassword, newPassword }).subscribe({
      next: () => {
        this.busy.set(false);
        this.form.reset();
        this.notifications.success('Password changed.');
      },
      error: (error: unknown) => {
        this.busy.set(false);
        const parsed = parseError(error);
        this.error.set(parsed);
        // The server revokes sessions on some password paths. If this one came back
        // unauthenticated, the token is already void - stay honest and sign out
        // rather than leaving a dead session on screen.
        if (parsed.status === 401) {
          this.auth.forceSignOut();
        }
      },
    });
  }
}
