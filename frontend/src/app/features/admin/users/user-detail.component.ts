import { ChangeDetectionStrategy, Component, effect, inject, input, signal } from '@angular/core';
import { FormsModule } from '@angular/forms';
import { Router, RouterLink } from '@angular/router';
import { RolesApi } from '../../../core/api/roles.api';
import { SessionsApi } from '../../../core/api/sessions.api';
import { UsersApi } from '../../../core/api/users.api';
import { AuthService } from '../../../core/auth/auth.service';
import { RoleResponse } from '../../../core/models/role';
import { USER_STATUSES, UserResponse, UserStatus } from '../../../core/models/user';
import { NotificationsService } from '../../../core/notifications.service';
import { InstantPipe, isLockedNow, userStatusTone } from '../../../shared/format';
import { BadgeComponent } from '../../../shared/ui/badge.component';
import { ConfirmService } from '../../../shared/ui/confirm.service';

/**
 * One account, and everything an administrator can do to it.
 *
 * Each action is a separate endpoint on the server, so each is a separate control
 * here rather than one "save" button that fires several writes and leaves the
 * account half-changed if one of them fails.
 */
@Component({
  selector: 'app-user-detail',
  changeDetection: ChangeDetectionStrategy.OnPush,
  imports: [FormsModule, RouterLink, BadgeComponent, InstantPipe],
  template: `
    <div class="page-header">
      <div>
        <h1>{{ user()?.email ?? 'User' }}</h1>
        <p class="page-header__subtitle">
          <a routerLink="/admin/users">← All users</a>
        </p>
      </div>
    </div>

    @if (loading()) {
      <p class="muted">Loading…</p>
    } @else if (user(); as target) {
      <section class="card">
        <dl class="facts">
          <div>
            <dt>Status</dt>
            <dd>
              <app-badge [label]="target.status" [tone]="tone(target.status)" />
              @if (locked(target)) {
                <app-badge label="Locked" tone="danger" />
              }
            </dd>
          </div>
          <div>
            <dt>Email verified</dt>
            <dd>{{ target.emailVerified ? 'Yes' : 'No' }}</dd>
          </div>
          <div>
            <dt>Created</dt>
            <dd>{{ target.createdAt | instant }}</dd>
          </div>
          <div>
            <dt>Last sign-in</dt>
            <dd>{{ target.lastLoginAt | instant }}</dd>
          </div>
          @if (locked(target)) {
            <div>
              <dt>Locked until</dt>
              <dd>{{ target.lockedUntil | instant }}</dd>
            </div>
          }
          <div>
            <dt>User id</dt>
            <dd class="mono">{{ target.id }}</dd>
          </div>
        </dl>
      </section>

      @if (canUpdate()) {
        <section class="card mt-3">
          <h2>Status</h2>
          <div class="inline">
            <select [ngModel]="target.status" (ngModelChange)="changeStatus($event)" name="status">
              @for (option of statuses; track option) {
                <option [value]="option">{{ option }}</option>
              }
            </select>
            <p class="field__hint" style="margin: 0">
              Disabling an account stops new sign-ins. It does not end sessions that
              already exist - use Revoke sessions for that.
            </p>
          </div>
        </section>

        <section class="card mt-3">
          <h2>Email address</h2>
          <div class="inline">
            <input type="email" [ngModel]="emailDraft()" (ngModelChange)="emailDraft.set($event)" name="email" />
            <button type="button" class="btn" [disabled]="busy()" (click)="changeEmail()">Update</button>
          </div>
        </section>

        <section class="card mt-3">
          <h2>Roles</h2>
          <p class="field__hint" style="margin-bottom: 0.75rem">
            Permission changes take effect on this user's next token refresh, without
            them signing out.
          </p>
          @if (allRoles().length === 0) {
            <p class="muted" style="font-size: 0.85rem">
              You need ROLE_READ to list the available roles.
            </p>
          } @else {
            <div class="role-grid">
              @for (role of allRoles(); track role.id) {
                <label class="checkbox">
                  <input
                    type="checkbox"
                    [checked]="assigned().has(role.id)"
                    (change)="toggleRole(role.id)"
                  />
                  <span>
                    {{ role.name }}
                    @if (role.systemRole) {
                      <span class="chip">system</span>
                    }
                  </span>
                </label>
              }
            </div>
            <button type="button" class="btn btn--primary mt-2" [disabled]="busy()" (click)="saveRoles()">
              Save roles
            </button>
          }
        </section>
      }

      <section class="card mt-3">
        <h2>Actions</h2>
        <div class="actions">
          @if (canUpdate() && locked(target)) {
            <button type="button" class="btn" (click)="unlock()">Clear lockout</button>
          }
          @if (canRevokeSessions()) {
            <button type="button" class="btn" (click)="revokeSessions()">Revoke all sessions</button>
          }
          @if (canDelete()) {
            <button type="button" class="btn btn--danger-quiet" (click)="remove()">Delete account</button>
          }
        </div>
      </section>
    }
  `,
  styles: `
    .facts { margin: 0; display: grid; gap: 0.85rem; }
    .facts > div { display: grid; grid-template-columns: 150px 1fr; gap: 1rem; align-items: baseline; }
    dt { color: var(--fg-muted); font-size: 0.8rem; }
    dd { margin: 0; overflow-wrap: anywhere; }
    .inline { display: flex; gap: 0.75rem; align-items: center; flex-wrap: wrap; }
    .inline select, .inline input { width: auto; min-width: 16rem; }
    .role-grid { display: grid; gap: 0.35rem; grid-template-columns: repeat(auto-fill, minmax(15rem, 1fr)); }
    .actions { display: flex; gap: 0.6rem; flex-wrap: wrap; }
    @media (max-width: 560px) {
      .facts > div { grid-template-columns: 1fr; gap: 0.15rem; }
    }
  `,
})
export class UserDetailComponent {
  private readonly api = inject(UsersApi);
  private readonly rolesApi = inject(RolesApi);
  private readonly sessionsApi = inject(SessionsApi);
  private readonly confirm = inject(ConfirmService);
  private readonly notifications = inject(NotificationsService);
  private readonly auth = inject(AuthService);
  private readonly router = inject(Router);

  /** Bound from the :id route parameter by withComponentInputBinding(). */
  readonly id = input<string>('');

  protected readonly statuses = USER_STATUSES;
  protected readonly tone = userStatusTone;
  protected readonly locked = (user: UserResponse) => isLockedNow(user.lockedUntil);

  protected readonly user = signal<UserResponse | null>(null);
  protected readonly allRoles = signal<RoleResponse[]>([]);
  protected readonly assigned = signal<ReadonlySet<string>>(new Set());
  protected readonly emailDraft = signal('');
  protected readonly loading = signal(true);
  protected readonly busy = signal(false);

  protected readonly canUpdate = () => this.auth.has('USER_UPDATE');
  protected readonly canDelete = () => this.auth.has('USER_DELETE');
  protected readonly canRevokeSessions = () => this.auth.has('SESSION_ADMIN');

  constructor() {
    effect(() => {
      const id = this.id();
      if (id) {
        this.load(id);
      }
    });

    if (this.auth.has('ROLE_READ')) {
      this.rolesApi.list().subscribe((roles) => {
        this.allRoles.set(roles);
        this.syncAssigned();
      });
    }
  }

  private load(id: string): void {
    this.loading.set(true);
    this.api.get(id).subscribe({
      next: (user) => {
        this.user.set(user);
        this.emailDraft.set(user.email);
        this.loading.set(false);
        this.syncAssigned();
      },
      error: () => this.loading.set(false),
    });
  }

  /**
   * The user record carries role names, the assignment endpoint takes role ids, so
   * the two lists have to be matched up once both have arrived.
   */
  private syncAssigned(): void {
    const user = this.user();
    const roles = this.allRoles();
    if (!user || roles.length === 0) {
      return;
    }
    const names = new Set(user.roles);
    this.assigned.set(new Set(roles.filter((role) => names.has(role.name)).map((role) => role.id)));
  }

  protected toggleRole(id: string): void {
    this.assigned.update((current) => {
      const next = new Set(current);
      if (!next.delete(id)) {
        next.add(id);
      }
      return next;
    });
  }

  protected changeStatus(status: UserStatus): void {
    const user = this.user();
    if (!user || status === user.status) {
      return;
    }
    this.busy.set(true);
    this.api.updateStatus(user.id, { status }).subscribe({
      next: (updated) => {
        this.busy.set(false);
        this.user.set(updated);
        this.notifications.success('Status updated.');
      },
      error: () => this.busy.set(false),
    });
  }

  protected changeEmail(): void {
    const user = this.user();
    const email = this.emailDraft().trim();
    if (!user || !email || email === user.email) {
      return;
    }
    this.busy.set(true);
    this.api.updateEmail(user.id, { email }).subscribe({
      next: (updated) => {
        this.busy.set(false);
        this.user.set(updated);
        this.notifications.success('Email updated.');
      },
      error: () => this.busy.set(false),
    });
  }

  protected saveRoles(): void {
    const user = this.user();
    if (!user) {
      return;
    }
    this.busy.set(true);
    this.api.assignRoles(user.id, { roleIds: [...this.assigned()] }).subscribe({
      next: (updated) => {
        this.busy.set(false);
        this.user.set(updated);
        this.notifications.success('Roles updated.');
      },
      error: () => this.busy.set(false),
    });
  }

  protected unlock(): void {
    const user = this.user();
    if (!user) {
      return;
    }
    this.api.unlock(user.id).subscribe(() => {
      this.notifications.success('Lockout cleared.');
      this.load(user.id);
    });
  }

  protected async revokeSessions(): Promise<void> {
    const user = this.user();
    if (!user) {
      return;
    }
    const confirmed = await this.confirm.ask({
      title: 'Revoke every session?',
      message:
        user.email + ' will be signed out on every device immediately, including the one they are using now.',
      confirmLabel: 'Revoke sessions',
      destructive: true,
    });
    if (!confirmed) {
      return;
    }
    this.sessionsApi.revokeForUser(user.id).subscribe((response) => {
      this.notifications.success(response.message);
    });
  }

  protected async remove(): Promise<void> {
    const user = this.user();
    if (!user) {
      return;
    }
    const confirmed = await this.confirm.ask({
      title: 'Delete this account?',
      message: 'Deleting ' + user.email + ' cannot be undone from this console.',
      confirmLabel: 'Delete account',
      destructive: true,
    });
    if (!confirmed) {
      return;
    }
    this.api.delete(user.id).subscribe(() => {
      this.notifications.success('Account deleted.');
      void this.router.navigate(['/admin/users']);
    });
  }
}
