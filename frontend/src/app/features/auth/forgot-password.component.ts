import { ChangeDetectionStrategy, Component, computed, inject, signal } from '@angular/core';
import { FormBuilder, ReactiveFormsModule, Validators } from '@angular/forms';
import { RouterLink } from '@angular/router';
import { AuthApi } from '../../core/api/auth.api';
import { ParsedError, errorText, parseError } from '../../core/http/api-error';
import { AlertComponent } from '../../shared/ui/alert.component';
import { AuthCardComponent } from './auth-card.component';

/**
 * Requests a password reset link.
 *
 * Like registration, the response is fixed and generic. The screen must not hint at
 * whether the address exists - not by wording, and not by showing a different
 * outcome for an unknown address.
 */
@Component({
  selector: 'app-forgot-password',
  changeDetection: ChangeDetectionStrategy.OnPush,
  imports: [ReactiveFormsModule, RouterLink, AuthCardComponent, AlertComponent],
  template: `
    <app-auth-card
      heading="Reset your password"
      subheading="Enter your email address and we will send a reset link if an account exists."
    >
      @if (sent(); as message) {
        <app-alert [text]="message" kind="success" />
        <p class="field__hint mt-2">The link expires in 30 minutes.</p>
        <p class="mt-3"><a routerLink="/login">Back to sign in</a></p>
      } @else {
        <form [formGroup]="form" (ngSubmit)="submit()" novalidate>
          <app-alert [text]="errorMessage()" [correlationId]="error()?.correlationId ?? null" />

          <label class="field mt-2">
            <span class="field__label">Email</span>
            <input type="email" formControlName="email" autocomplete="username" autofocus />
          </label>

          <button type="submit" class="btn btn--primary" style="width: 100%" [disabled]="busy()">
            {{ busy() ? 'Sending…' : 'Send reset link' }}
          </button>
        </form>
        <p class="mt-3" style="font-size: 0.83rem"><a routerLink="/login">Back to sign in</a></p>
      }
    </app-auth-card>
  `,
})
export class ForgotPasswordComponent {
  private readonly fb = inject(FormBuilder);
  private readonly api = inject(AuthApi);

  protected readonly busy = signal(false);
  protected readonly sent = signal<string | null>(null);
  protected readonly error = signal<ParsedError | null>(null);
  protected readonly errorMessage = computed(() => {
    const parsed = this.error();
    return parsed ? errorText(parsed) : null;
  });

  protected readonly form = this.fb.nonNullable.group({
    email: ['', [Validators.required, Validators.email]],
  });

  protected submit(): void {
    if (this.form.invalid || this.busy()) {
      this.form.markAllAsTouched();
      return;
    }
    this.busy.set(true);
    this.error.set(null);

    this.api.forgotPassword(this.form.getRawValue()).subscribe({
      next: (response) => {
        this.busy.set(false);
        this.sent.set(response.message);
      },
      error: (error: unknown) => {
        this.busy.set(false);
        this.error.set(parseError(error));
      },
    });
  }
}
