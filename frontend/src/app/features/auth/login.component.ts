import { ChangeDetectionStrategy, Component, computed, inject, input, signal } from '@angular/core';
import { FormBuilder, ReactiveFormsModule, Validators } from '@angular/forms';
import { Router, RouterLink } from '@angular/router';
import { AuthApi } from '../../core/api/auth.api';
import { AuthService } from '../../core/auth/auth.service';
import { ParsedError, errorText, parseError } from '../../core/http/api-error';
import { AlertComponent } from '../../shared/ui/alert.component';
import { AuthCardComponent } from './auth-card.component';
import { isExternal, safeReturnTo } from './return-to';

/**
 * The hosted login screen.
 *
 * Two jobs. Signing a user into the console, and completing the OAuth2 handshake:
 * when /oauth2/authorize finds no session it sends the browser here with the whole
 * authorize URL in return_to, and once the SSO cookie exists the request is replayed
 * rather than reconstructed.
 */
@Component({
  selector: 'app-login',
  changeDetection: ChangeDetectionStrategy.OnPush,
  imports: [ReactiveFormsModule, RouterLink, AuthCardComponent, AlertComponent],
  template: `
    <app-auth-card
      heading="Sign in"
      [subheading]="continuingFlow() ? 'Sign in to continue to the application that sent you here.' : null"
    >
      <form [formGroup]="form" (ngSubmit)="submit()" novalidate>
        <app-alert [text]="errorMessage()" [correlationId]="error()?.correlationId ?? null" />
        <app-alert [text]="notice()" kind="success" />

        <label class="field mt-2">
          <span class="field__label">Email</span>
          <input
            type="email"
            formControlName="email"
            autocomplete="username"
            autofocus
            [attr.aria-invalid]="isInvalid('email') ? 'true' : null"
          />
          @if (isInvalid('email')) {
            <p class="field__error">Enter a valid email address.</p>
          }
        </label>

        <label class="field">
          <span class="field__label">Password</span>
          <input
            type="password"
            formControlName="password"
            autocomplete="current-password"
            [attr.aria-invalid]="isInvalid('password') ? 'true' : null"
          />
          @if (isInvalid('password')) {
            <p class="field__error">Enter your password.</p>
          }
        </label>

        <button type="submit" class="btn btn--primary" style="width: 100%" [disabled]="busy()">
          {{ busy() ? 'Signing in…' : 'Sign in' }}
        </button>

        @if (canResendVerification()) {
          <p class="field__hint mt-2">
            Not verified yet?
            <button type="button" class="btn--link" (click)="resendVerification()" [disabled]="busy()">
              Send the link again
            </button>
          </p>
        }
      </form>

      <p class="links">
        <a routerLink="/forgot-password">Forgot your password?</a>
        <a routerLink="/register">Create an account</a>
      </p>
    </app-auth-card>
  `,
  styles: `
    .links {
      display: flex;
      justify-content: space-between;
      gap: 1rem;
      margin: 1.1rem 0 0;
      font-size: 0.83rem;
    }
  `,
})
export class LoginComponent {
  private readonly fb = inject(FormBuilder);
  private readonly auth = inject(AuthService);
  private readonly authApi = inject(AuthApi);
  private readonly router = inject(Router);

  /** Set by /oauth2/authorize when it needs a session before it can continue. */
  readonly returnTo = input<string | undefined>(undefined, { alias: 'return_to' });

  protected readonly busy = signal(false);
  protected readonly error = signal<ParsedError | null>(null);
  protected readonly notice = signal<string | null>(null);
  protected readonly errorMessage = computed(() => {
    const parsed = this.error();
    return parsed ? errorText(parsed) : null;
  });

  protected readonly continuingFlow = computed(() => safeReturnTo(this.returnTo()) !== null);

  /** The one failure the user can act on directly from this screen. */
  protected readonly canResendVerification = computed(
    () => this.error()?.code === 'EMAIL_NOT_VERIFIED',
  );

  protected readonly form = this.fb.nonNullable.group({
    email: ['', [Validators.required, Validators.email]],
    password: ['', [Validators.required]],
  });

  protected isInvalid(control: 'email' | 'password'): boolean {
    const field = this.form.controls[control];
    return field.invalid && (field.dirty || field.touched);
  }

  protected submit(): void {
    if (this.form.invalid || this.busy()) {
      this.form.markAllAsTouched();
      return;
    }
    this.busy.set(true);
    this.error.set(null);
    this.notice.set(null);

    this.auth.login(this.form.getRawValue()).subscribe({
      next: () => this.continueAfterLogin(),
      error: (error: unknown) => {
        this.busy.set(false);
        this.error.set(parseError(error));
      },
    });
  }

  protected resendVerification(): void {
    const email = this.form.controls.email.value;
    if (!email) {
      return;
    }
    this.busy.set(true);
    this.authApi.resendVerification({ email }).subscribe({
      next: (response) => {
        this.busy.set(false);
        this.error.set(null);
        this.notice.set(response.message);
      },
      error: (error: unknown) => {
        this.busy.set(false);
        this.error.set(parseError(error));
      },
    });
  }

  /**
   * Hands the browser back to whatever sent it here.
   *
   * A returning OAuth request points at the backend, so it needs a real navigation
   * rather than a router hop - the router would try to match /oauth2/authorize as
   * one of this app's routes.
   */
  private continueAfterLogin(): void {
    const destination = safeReturnTo(this.returnTo());
    if (destination && isExternal(destination)) {
      location.assign(destination);
      return;
    }
    void this.router.navigateByUrl(destination ?? '/');
  }
}

