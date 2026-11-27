import { ChangeDetectionStrategy, Component, computed, inject, signal } from '@angular/core';
import { FormBuilder, ReactiveFormsModule, Validators } from '@angular/forms';
import { RouterLink } from '@angular/router';
import { AuthApi } from '../../core/api/auth.api';
import { ParsedError, errorText, parseError } from '../../core/http/api-error';
import { PASSWORD_RULES, passwordPolicyValidator } from '../../shared/password-policy';
import { AlertComponent } from '../../shared/ui/alert.component';
import { AuthCardComponent } from './auth-card.component';

/**
 * Registration.
 *
 * The server answers identically whether or not the address was already taken, so
 * that this form cannot be used to enumerate accounts. The screen mirrors that: on
 * success it always says the same thing, and never implies an account was created.
 */
@Component({
  selector: 'app-register',
  changeDetection: ChangeDetectionStrategy.OnPush,
  imports: [ReactiveFormsModule, RouterLink, AuthCardComponent, AlertComponent],
  template: `
    <app-auth-card
      heading="Create an account"
      subheading="You will get a verification link by email before you can sign in."
    >
      @if (submitted(); as message) {
        <app-alert [text]="message" kind="success" />
        <p class="field__hint mt-2">
          Check your inbox. The link is single-use and expires in 24 hours.
        </p>
        <p class="mt-3"><a routerLink="/login">Back to sign in</a></p>
      } @else {
        <form [formGroup]="form" (ngSubmit)="submit()" novalidate>
          <app-alert [text]="errorMessage()" [correlationId]="error()?.correlationId ?? null" />

          <label class="field mt-2">
            <span class="field__label">Email</span>
            <input type="email" formControlName="email" autocomplete="username" autofocus />
            @if (isInvalid('email')) {
              <p class="field__error">Enter a valid email address.</p>
            }
          </label>

          <label class="field">
            <span class="field__label">Password</span>
            <input type="password" formControlName="password" autocomplete="new-password" />
            @if (isInvalid('password')) {
              @if (form.controls.password.hasError('required')) {
                <p class="field__error">Enter a password.</p>
              } @else {
                @for (message of form.controls.password.getError('passwordPolicy'); track message) {
                  <p class="field__error">{{ message }}</p>
                }
              }
            }
          </label>

          <ul class="rules">
            @for (rule of rules; track rule.label) {
              <li [class.rules__met]="rule.satisfied(passwordValue())">
                <span aria-hidden="true">{{ rule.satisfied(passwordValue()) ? '✓' : '·' }}</span>
                {{ rule.label }}
              </li>
            }
          </ul>

          <button type="submit" class="btn btn--primary mt-2" style="width: 100%" [disabled]="busy()">
            {{ busy() ? 'Creating…' : 'Create account' }}
          </button>
        </form>

        <p class="mt-3" style="font-size: 0.83rem">
          Already have an account? <a routerLink="/login">Sign in</a>
        </p>
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
export class RegisterComponent {
  private readonly fb = inject(FormBuilder);
  private readonly api = inject(AuthApi);

  protected readonly rules = PASSWORD_RULES;
  protected readonly busy = signal(false);
  protected readonly submitted = signal<string | null>(null);
  protected readonly error = signal<ParsedError | null>(null);
  protected readonly errorMessage = computed(() => {
    const parsed = this.error();
    return parsed ? errorText(parsed) : null;
  });

  protected readonly form = this.fb.nonNullable.group({
    email: ['', [Validators.required, Validators.email]],
    password: ['', [Validators.required, passwordPolicyValidator()]],
  });

  /** Drives the live checklist under the password field. */
  protected passwordValue(): string {
    return this.form.controls.password.value;
  }

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

    this.api.register(this.form.getRawValue()).subscribe({
      next: (response) => {
        this.busy.set(false);
        this.submitted.set(response.message);
      },
      error: (error: unknown) => {
        this.busy.set(false);
        this.error.set(parseError(error));
      },
    });
  }
}
