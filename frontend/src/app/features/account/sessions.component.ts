import { ChangeDetectionStrategy, Component, inject, signal } from '@angular/core';
import { SessionsApi } from '../../core/api/sessions.api';
import { AuthService } from '../../core/auth/auth.service';
import { SessionResponse } from '../../core/models/session';
import { NotificationsService } from '../../core/notifications.service';
import { InstantPipe, OrDashPipe } from '../../shared/format';
import { BadgeComponent } from '../../shared/ui/badge.component';
import { ConfirmService } from '../../shared/ui/confirm.service';

/**
 * Every device currently signed in as this user, with the ability to cut any of
 * them off.
 *
 * Sessions live in PostgreSQL and Redis rather than in the instance, so revoking
 * one takes effect everywhere immediately, not when some cache happens to expire.
 */
@Component({
  selector: 'app-sessions',
  changeDetection: ChangeDetectionStrategy.OnPush,
  imports: [BadgeComponent, InstantPipe, OrDashPipe],
  template: `
    <div class="page-header">
      <div>
        <h1>Devices</h1>
        <p class="page-header__subtitle">
          Where your account is signed in. Revoking a session ends it immediately, along
          with any access token it issued.
        </p>
      </div>
      @if (sessions().length > 1) {
        <button type="button" class="btn btn--danger-quiet" (click)="revokeAll()">
          Sign out everywhere else
        </button>
      }
    </div>

    <section class="card">
      @if (loading()) {
        <p class="muted">Loading…</p>
      } @else if (sessions().length === 0) {
        <p class="empty">No active sessions.</p>
      } @else {
        <div class="table-wrap">
          <table class="data">
            <thead>
              <tr>
                <th>Device</th>
                <th>IP address</th>
                <th>Application</th>
                <th class="time">Signed in</th>
                <th class="time">Last seen</th>
                <th class="time">Expires</th>
                <th></th>
              </tr>
            </thead>
            <tbody>
              @for (session of sessions(); track session.id) {
                <tr>
                  <td>
                    {{ session.deviceInfo | orDash }}
                    @if (session.current) {
                      <app-badge label="This device" tone="ok" />
                    }
                  </td>
                  <td class="mono">{{ session.ipAddress | orDash }}</td>
                  <td>{{ session.clientId | orDash }}</td>
                  <td class="time">{{ session.createdAt | instant }}</td>
                  <td class="time">{{ session.lastSeenAt | instant }}</td>
                  <td class="time">{{ session.expiresAt | instant }}</td>
                  <td>
                    <div class="row-actions">
                      <button type="button" class="btn btn--sm" (click)="revoke(session)">
                        {{ session.current ? 'Sign out' : 'Revoke' }}
                      </button>
                    </div>
                  </td>
                </tr>
              }
            </tbody>
          </table>
        </div>
      }
    </section>
  `,
})
export class SessionsComponent {
  private readonly api = inject(SessionsApi);
  private readonly confirm = inject(ConfirmService);
  private readonly notifications = inject(NotificationsService);
  private readonly auth = inject(AuthService);

  protected readonly sessions = signal<SessionResponse[]>([]);
  protected readonly loading = signal(true);

  constructor() {
    this.load();
  }

  private load(): void {
    this.loading.set(true);
    this.api.mine().subscribe({
      next: (sessions) => {
        this.sessions.set(sessions);
        this.loading.set(false);
      },
      error: () => this.loading.set(false),
    });
  }

  protected async revoke(session: SessionResponse): Promise<void> {
    const isCurrent = session.current;
    const confirmed = await this.confirm.ask({
      title: isCurrent ? 'Sign out of this device?' : 'Revoke this session?',
      message: isCurrent
        ? 'You will be returned to the sign-in screen.'
        : 'That device will have to sign in again. Any token it holds stops working straight away.',
      confirmLabel: isCurrent ? 'Sign out' : 'Revoke',
      destructive: true,
    });
    if (!confirmed) {
      return;
    }

    this.api.revoke(session.id).subscribe(() => {
      if (isCurrent) {
        // Revoking your own session invalidates the token this page is using. There
        // is nothing left to reload with.
        this.auth.forceSignOut();
        return;
      }
      this.notifications.success('Session revoked.');
      this.load();
    });
  }

  protected async revokeAll(): Promise<void> {
    const confirmed = await this.confirm.ask({
      title: 'Sign out everywhere else?',
      message:
        'Every other device will be signed out immediately. This device stays signed in.',
      confirmLabel: 'Sign out everywhere else',
      destructive: true,
    });
    if (!confirmed) {
      return;
    }

    this.api.revokeAll().subscribe(() => {
      this.notifications.success('Other sessions revoked.');
      this.load();
    });
  }
}
