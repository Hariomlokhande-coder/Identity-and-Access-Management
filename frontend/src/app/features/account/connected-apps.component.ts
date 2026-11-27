import { ChangeDetectionStrategy, Component, inject, signal } from '@angular/core';
import { OAuthApi } from '../../core/api/oauth.api';
import { AuthService } from '../../core/auth/auth.service';
import { GrantedConsent } from '../../core/models/oauth';
import { NotificationsService } from '../../core/notifications.service';
import { InstantPipe } from '../../shared/format';
import { ConfirmService } from '../../shared/ui/confirm.service';
import { describeScope } from '../consent/scopes';

/**
 * Applications this user has authorized, and the ability to take that back.
 *
 * Withdrawing is not just a database row: the server also revokes the user's other
 * sessions, because a withdrawal that left the application holding live tokens
 * would not be a withdrawal. The confirmation says so.
 */
@Component({
  selector: 'app-connected-apps',
  changeDetection: ChangeDetectionStrategy.OnPush,
  imports: [InstantPipe],
  template: `
    <div class="page-header">
      <div>
        <h1>Connected apps</h1>
        <p class="page-header__subtitle">
          Applications you have allowed to act on your behalf.
        </p>
      </div>
    </div>

    @if (loading()) {
      <p class="muted">Loading…</p>
    } @else if (consents().length === 0) {
      <section class="card">
        <p class="empty">You have not authorized any applications.</p>
      </section>
    } @else {
      <ul class="apps">
        @for (consent of consents(); track consent.clientApplicationId) {
          <li class="app">
            <div class="app__head">
              <div>
                <h2 class="app__name">{{ consent.clientName }}</h2>
                <p class="app__id mono">{{ consent.clientId }}</p>
              </div>
              <button type="button" class="btn btn--sm btn--danger-quiet" (click)="withdraw(consent)">
                Withdraw
              </button>
            </div>

            <p class="app__label">Granted access to:</p>
            <ul class="app__scopes">
              @for (scope of consent.scopes; track scope) {
                <li>{{ describe(scope).title }}</li>
              } @empty {
                <li>Confirm who you are</li>
              }
            </ul>

            <p class="app__granted">Authorized {{ consent.grantedAt | instant }}</p>
          </li>
        }
      </ul>
    }
  `,
  styles: `
    .apps {
      list-style: none;
      margin: 0;
      padding: 0;
      background: var(--surface);
      border-block: 1px solid var(--border);
    }
    .app { padding: 1.1rem clamp(0.85rem, 4vw, 1.5rem); }
    .app + .app { border-top: 1px solid var(--border); }
    .app__head { display: flex; justify-content: space-between; gap: 1rem; align-items: flex-start; }
    .app__name { margin: 0; font-size: 1rem; }
    .app__id { margin: 0.15rem 0 0; font-size: 0.72rem; color: var(--fg-muted); overflow-wrap: anywhere; }
    .app__label { margin: 1rem 0 0.3rem; font-size: 0.76rem; color: var(--fg-muted); }
    .app__scopes { margin: 0; padding-left: 1.1rem; font-size: 0.84rem; display: grid; gap: 0.1rem; }
    .app__granted { margin: 1rem 0 0; font-size: 0.76rem; color: var(--fg-muted); }
  `,
})
export class ConnectedAppsComponent {
  private readonly api = inject(OAuthApi);
  private readonly confirm = inject(ConfirmService);
  private readonly notifications = inject(NotificationsService);
  private readonly auth = inject(AuthService);

  protected readonly consents = signal<GrantedConsent[]>([]);
  protected readonly loading = signal(true);
  protected readonly describe = describeScope;

  constructor() {
    this.load();
  }

  private load(): void {
    this.loading.set(true);
    this.api.granted().subscribe({
      next: (consents) => {
        this.consents.set(consents);
        this.loading.set(false);
      },
      error: () => this.loading.set(false),
    });
  }

  protected async withdraw(consent: GrantedConsent): Promise<void> {
    const confirmed = await this.confirm.ask({
      title: 'Withdraw access for ' + consent.clientName + '?',
      message:
        'It will lose access immediately, and you will be signed out of your other devices. ' +
        'Authorizing it again will ask for your consent from scratch.',
      confirmLabel: 'Withdraw access',
      destructive: true,
    });
    if (!confirmed) {
      return;
    }

    this.api.withdraw(consent.clientApplicationId).subscribe({
      next: () => {
        this.notifications.success('Access withdrawn.');
        this.load();
      },
      error: () => {
        // The revocation also cuts other sessions; if this one went with it there is
        // nothing to reload against.
        this.auth.ensureSession().subscribe();
      },
    });
  }
}
