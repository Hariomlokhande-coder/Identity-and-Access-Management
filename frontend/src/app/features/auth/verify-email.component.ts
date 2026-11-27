import { ChangeDetectionStrategy, Component, effect, inject, input, signal } from '@angular/core';
import { RouterLink } from '@angular/router';
import { AuthApi } from '../../core/api/auth.api';
import { errorText, parseError } from '../../core/http/api-error';
import { AlertComponent } from '../../shared/ui/alert.component';
import { AuthCardComponent } from './auth-card.component';

type State = 'verifying' | 'done' | 'failed' | 'missing';

/**
 * The landing page for the link in a verification email.
 *
 * The token is spent as soon as the page opens. A link that has already been used,
 * or superseded by a newer one, fails here - so the screen offers to send a fresh
 * one rather than leaving the user stuck on an error.
 */
@Component({
  selector: 'app-verify-email',
  changeDetection: ChangeDetectionStrategy.OnPush,
  imports: [RouterLink, AuthCardComponent, AlertComponent],
  template: `
    <app-auth-card heading="Verify your email">
      @switch (state()) {
        @case ('verifying') {
          <p class="muted">Checking your link…</p>
        }
        @case ('done') {
          <app-alert [text]="message()" kind="success" />
          <p class="mt-3"><a class="btn btn--primary" routerLink="/login">Continue to sign in</a></p>
        }
        @case ('missing') {
          <app-alert text="This link is missing its token. Open the link from your email again." />
        }
        @case ('failed') {
          <app-alert [text]="message()" />
          <p class="field__hint mt-2">
            Links are single-use, and requesting a new one replaces the old. If you have
            asked more than once, only the newest link works.
          </p>

          <form class="mt-2" (submit)="resend($event)">
            <label class="field">
              <span class="field__label">Send a new link to</span>
              <input type="email" name="email" [value]="email()" (input)="onEmail($event)" />
            </label>
            <button type="submit" class="btn" [disabled]="busy() || !email()">
              {{ busy() ? 'Sending…' : 'Send a new link' }}
            </button>
          </form>
          @if (resent(); as text) {
            <div class="mt-2"><app-alert [text]="text" kind="success" /></div>
          }
        }
      }
    </app-auth-card>
  `,
})
export class VerifyEmailComponent {
  private readonly api = inject(AuthApi);

  /** Comes from the link in the email: /verify-email?token=... */
  readonly token = input<string | undefined>(undefined);

  protected readonly state = signal<State>('verifying');
  protected readonly message = signal<string | null>(null);
  protected readonly email = signal('');
  protected readonly busy = signal(false);
  protected readonly resent = signal<string | null>(null);

  constructor() {
    // The token arrives as a routed input, so the call belongs in an effect rather
    // than a constructor body - the input is not bound yet when the class is built.
    effect(() => {
      const token = this.token();
      if (!token) {
        this.state.set('missing');
        return;
      }
      this.api.verifyEmail({ token }).subscribe({
        next: (response) => {
          this.message.set(response.message);
          this.state.set('done');
        },
        error: (error: unknown) => {
          this.message.set(errorText(parseError(error)));
          this.state.set('failed');
        },
      });
    });
  }

  protected onEmail(event: Event): void {
    this.email.set((event.target as HTMLInputElement).value);
  }

  protected resend(event: Event): void {
    event.preventDefault();
    const email = this.email();
    if (!email || this.busy()) {
      return;
    }
    this.busy.set(true);
    this.api.resendVerification({ email }).subscribe({
      next: (response) => {
        this.busy.set(false);
        this.resent.set(response.message);
      },
      error: (error: unknown) => {
        this.busy.set(false);
        this.message.set(errorText(parseError(error)));
      },
    });
  }
}
