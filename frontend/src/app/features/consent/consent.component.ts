import { ChangeDetectionStrategy, Component, effect, inject, input, signal } from '@angular/core';
import { Router } from '@angular/router';
import { OAuthApi } from '../../core/api/oauth.api';
import { PendingAuthorization } from '../../core/models/oauth';
import { errorText, parseError } from '../../core/http/api-error';
import { AlertComponent } from '../../shared/ui/alert.component';
import { AuthCardComponent } from '../auth/auth-card.component';
import { describeScope } from './scopes';

/**
 * The consent screen: iam.consent-url points here.
 *
 * The authorize endpoint sends the browser here with a request_id when a client
 * needs the user's agreement. Everything about the request is fetched from the
 * server by that id - nothing describing the grant is taken from the query string,
 * because a client name or scope list read out of the URL is a client-controlled
 * string on a screen whose whole job is to be trusted.
 */
@Component({
  selector: 'app-consent',
  changeDetection: ChangeDetectionStrategy.OnPush,
  imports: [AuthCardComponent, AlertComponent],
  template: `
    <app-auth-card
      [heading]="request() ? 'Authorize ' + request()!.clientName : 'Authorize application'"
      [subheading]="request() ? 'This application is asking for access to your account.' : null"
    >
      @if (loading()) {
        <p class="muted">Loading the request…</p>
      } @else if (error(); as message) {
        <app-alert [text]="message" />
        <p class="field__hint mt-2">
          Start again from the application you were using. Authorization requests are
          short-lived and cannot be resumed once they lapse.
        </p>
      } @else if (request(); as pending) {
        <div class="client">
          <p class="client__id mono">{{ pending.clientId }}</p>
        </div>

        <p class="scopes__title">It will be able to:</p>
        <ul class="scopes">
          @for (scope of pending.scopes; track scope) {
            <li>
              <span class="scopes__name">{{ describe(scope).title }}</span>
              <span class="scopes__detail">{{ describe(scope).detail }}</span>
            </li>
          } @empty {
            <li><span class="scopes__name">Confirm who you are</span></li>
          }
        </ul>

        <div class="actions">
          <button type="button" class="btn" [disabled]="deciding()" (click)="decide(false)">
            Deny
          </button>
          <button type="button" class="btn btn--primary" [disabled]="deciding()" (click)="decide(true)">
            {{ deciding() ? 'Working…' : 'Allow' }}
          </button>
        </div>

        <p class="field__hint mt-2">
          You can withdraw this at any time from Connected apps in your account.
        </p>
      }
    </app-auth-card>
  `,
  styles: `
    .client {
      padding: 0.6rem 0.75rem;
      background: var(--surface-2);
      border: 1px solid var(--border);
      border-radius: 8px;
    }
    .client__id { margin: 0; color: var(--fg-muted); font-size: 0.76rem; overflow-wrap: anywhere; }

    .scopes__title { margin: 1.1rem 0 0.4rem; font-size: 0.82rem; font-weight: 600; }
    .scopes { list-style: none; margin: 0; padding: 0; display: grid; gap: 0.55rem; }
    .scopes li {
      display: grid;
      gap: 0.1rem;
      padding-left: 1.1rem;
      position: relative;
    }
    .scopes li::before {
      content: '·';
      position: absolute;
      left: 0.25rem;
      color: var(--accent);
      font-weight: 700;
    }
    .scopes__name { font-size: 0.88rem; }
    .scopes__detail { font-size: 0.78rem; color: var(--fg-muted); }

    .actions { display: flex; gap: 0.6rem; margin-top: 1.4rem; }
    .actions .btn { flex: 1; }
  `,
})
export class ConsentComponent {
  private readonly api = inject(OAuthApi);
  private readonly router = inject(Router);

  readonly requestId = input<string | undefined>(undefined, { alias: 'request_id' });

  protected readonly loading = signal(true);
  protected readonly deciding = signal(false);
  protected readonly request = signal<PendingAuthorization | null>(null);
  protected readonly error = signal<string | null>(null);

  protected readonly describe = describeScope;

  constructor() {
    effect(() => {
      const requestId = this.requestId();
      if (!requestId) {
        this.loading.set(false);
        this.error.set('This authorization link is incomplete.');
        return;
      }
      this.load(requestId);
    });
  }

  private load(requestId: string): void {
    this.loading.set(true);
    this.api.pending(requestId).subscribe({
      next: (pending) => {
        this.request.set(pending);
        this.loading.set(false);
      },
      error: (error: unknown) => {
        this.loading.set(false);
        const parsed = parseError(error);
        // The SSO cookie is missing or has expired. Sign in and come straight back:
        // the pending request survives, so the flow resumes where it left off.
        if (parsed.status === 401) {
          void this.router.navigate(['/login'], {
            queryParams: { return_to: location.href },
          });
          return;
        }
        this.error.set(errorText(parsed));
      },
    });
  }

  /**
   * Records the decision and hands the browser back to the client.
   *
   * A denial redirects too - the client is entitled to be told it was refused,
   * rather than being left waiting on a window that never comes back.
   */
  protected decide(approved: boolean): void {
    const pending = this.request();
    if (!pending || this.deciding()) {
      return;
    }
    this.deciding.set(true);

    this.api.decide({ requestId: pending.requestId, approved }).subscribe({
      next: (response) => location.assign(response.redirectUri),
      error: (error: unknown) => {
        this.deciding.set(false);
        this.error.set(errorText(parseError(error)));
      },
    });
  }
}
