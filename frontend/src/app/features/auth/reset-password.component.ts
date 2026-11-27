import { ChangeDetectionStrategy, Component, computed, inject, input, signal } from '@angular/core';
import { FormBuilder, ReactiveFormsModule, Validators } from '@angular/forms';
import { RouterLink } from '@angular/router';
import { AuthApi } from '../../core/api/auth.api';
import { ParsedError, errorText, parseError } from '../../core/http/api-error';
import {
  PASSWORD_RULES,
  passwordPolicyValidator,
  passwordsMatchValidator,
} from '../../shared/password-policy';
import { AlertComponent } from '../../shared/ui/alert.component';
import { AuthCardComponent } from './auth-card.component';

/**
 * Completes a password reset.
 *
 * Succeeding here revokes every session the account had, everywhere. That is the
 * point - a reset is what someone does when they think the account is compromised -
 * so the screen says so rather than letting it be a surprise.
 */
@Component({
  selector: 'app-reset-password',
  changeDetection: ChangeDetectionStrategy.OnPush,
  imports: [ReactiveFormsModule, RouterLink, AuthCardComponent, AlertComponent],
  template: `
    <app-auth-card
      heading="Choose a new password"
      subheading="Setting a new password signs you out on every device."
    >
      @if (!token()) {
        <app-alert text="This link is missing its token. Open the link from your email again." />
        <p class="mt-3"><a routerLink="/forgot-password">Request a new link</a></p>
      } @else if (done(); as message) {
        <app-alert [text]="message" kind="success" />
        <p class="mt-3"><a class="btn btn--primary" routerLink="/login">Sign in</a></p>
      } @else {
        <form [formGroup]="form" (ngSubmit)="submit()" novalidate>
          <app-alert [text]="errorMessage()" [correlationId]="error()?.correlationId ?? null" />

          <label class="field mt-2">
            <span class="field__label">New password</span>
            <input type="password" formControlName="newPassword" autocomplete="new-password" autofocus />
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

          <button type="submit" class="btn btn--primary" style="width: 100%" [disabled]="busy()">
            {{ busy() ? 'Saving…' : 'Set new password' }}
          </button>
        </form>
      }
    </app-auth-card>
  `,
  styles: `
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
export class ResetPasswordComponent {
  private readonly fb = inject(FormBuilder);
  private readonly api = inject(AuthApi);

  /** From the emailed link: /reset-password?token=... */
  readonly token = input<string | undefined>(undefined);

  protected readonly rules = PASSWORD_RULES;
  protected readonly busy = signal(false);
  protected readonly done = signal<string | null>(null);
  protected readonly error = signal<ParsedError | null>(null);
  protected readonly errorMessage = computed(() => {
    const parsed = this.error();
    return parsed ? errorText(parsed) : null;
  });

  protected readonly form = this.fb.nonNullable.group(
    {
      newPassword: ['', [Validators.required, passwordPolicyValidator()]],
      confirm: ['', [Validators.required]],
    },
    { validators: passwordsMatchValidator('newPassword', 'confirm') },
  );

  protected submit(): void {
    const token = this.token();
    if (!token || this.form.invalid || this.busy()) {
      this.form.markAllAsTouched();
      return;
    }
    this.busy.set(true);
    this.error.set(null);

    this.api
      .resetPassword({ token, newPassword: this.form.controls.newPassword.value })
      .subscribe({
        next: (response) => {
          this.busy.set(false);
          this.done.set(response.message);
        },
        error: (error: unknown) => {
          this.busy.set(false);
          this.error.set(parseError(error));
        },
      });
  }
}
