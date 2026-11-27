import { ChangeDetectionStrategy, Component, inject, signal } from '@angular/core';
import { FormsModule } from '@angular/forms';
import { RouterLink } from '@angular/router';
import { UsersApi } from '../../../core/api/users.api';
import { RolesApi } from '../../../core/api/roles.api';
import { AuthService } from '../../../core/auth/auth.service';
import { PageResponse } from '../../../core/models/common';
import { RoleResponse } from '../../../core/models/role';
import { USER_STATUSES, UserResponse, UserStatus } from '../../../core/models/user';
import { NotificationsService } from '../../../core/notifications.service';
import { InstantPipe, isLockedNow, userStatusTone } from '../../../shared/format';
import {
  PASSWORD_RULES,
  passwordPolicyValidator,
} from '../../../shared/password-policy';
import { FormBuilder, ReactiveFormsModule, Validators } from '@angular/forms';
import { BadgeComponent } from '../../../shared/ui/badge.component';
import { PaginatorComponent } from '../../../shared/ui/paginator.component';

const PAGE_SIZE = 25;

/** Search, create and triage user accounts. */
@Component({
  selector: 'app-user-list',
  changeDetection: ChangeDetectionStrategy.OnPush,
  imports: [
    FormsModule,
    ReactiveFormsModule,
    RouterLink,
    BadgeComponent,
    PaginatorComponent,
    InstantPipe,
  ],
  template: `
    <div class="page-header">
      <div>
        <h1>Users</h1>
        <p class="page-header__subtitle">Accounts on this platform.</p>
      </div>
      @if (canCreate()) {
        <button type="button" class="btn btn--primary" (click)="creating.set(!creating())">
          {{ creating() ? 'Cancel' : 'New user' }}
        </button>
      }
    </div>

    @if (creating()) {
      <section class="card mt-2" style="margin-bottom: 1.25rem">
        <h2>Create a user</h2>
        <form [formGroup]="createForm" (ngSubmit)="create()" novalidate>
          <div class="create-grid">
            <label class="field">
              <span class="field__label">Email</span>
              <input type="email" formControlName="email" autocomplete="off" />
            </label>
            <label class="field">
              <span class="field__label">Initial password</span>
              <input type="password" formControlName="password" autocomplete="new-password" />
            </label>
          </div>

          <ul class="rules">
            @for (rule of rules; track rule.label) {
              <li [class.rules__met]="rule.satisfied(createForm.controls.password.value)">
                <span aria-hidden="true">{{ rule.satisfied(createForm.controls.password.value) ? '✓' : '·' }}</span>
                {{ rule.label }}
              </li>
            }
          </ul>

          <label class="checkbox mt-2">
            <input type="checkbox" formControlName="emailVerified" />
            Mark the address as already verified
          </label>
          <p class="field__hint">
            Skips the verification email. Only do this when you know the address is real -
            it is the check that stops an account being created against someone else's inbox.
          </p>

          <fieldset class="roles">
            <legend class="field__label">Roles</legend>
            @for (role of roles(); track role.id) {
              <label class="checkbox">
                <input
                  type="checkbox"
                  [checked]="selectedRoles().has(role.id)"
                  (change)="toggleRole(role.id)"
                />
                {{ role.name }}
              </label>
            } @empty {
              <p class="muted" style="font-size: 0.82rem">No roles available.</p>
            }
          </fieldset>

          <button type="submit" class="btn btn--primary mt-2" [disabled]="busy() || createForm.invalid">
            {{ busy() ? 'Creating…' : 'Create user' }}
          </button>
        </form>
      </section>
    }

    <section class="card">
      <div class="toolbar">
        <label class="field" style="flex: 1 1 16rem">
          <span class="field__label">Search</span>
          <input
            type="search"
            placeholder="Email contains…"
            [ngModel]="query()"
            (ngModelChange)="query.set($event)"
            (keyup.enter)="reload(0)"
            name="query"
          />
        </label>
        <label class="field">
          <span class="field__label">Status</span>
          <select [ngModel]="status()" (ngModelChange)="onStatus($event)" name="status">
            <option value="">Any</option>
            @for (option of statuses; track option) {
              <option [value]="option">{{ option }}</option>
            }
          </select>
        </label>
        <button type="button" class="btn" (click)="reload(0)">Search</button>
      </div>

      @if (loading()) {
        <p class="muted">Loading…</p>
      } @else if (page().items.length === 0) {
        <p class="empty">No users match this search.</p>
      } @else {
        <div class="table-wrap">
          <table class="data">
            <thead>
              <tr>
                <th>Email</th>
                <th>Status</th>
                <th>Roles</th>
                <th class="time">Created</th>
                <th class="time">Last sign-in</th>
                <th></th>
              </tr>
            </thead>
            <tbody>
              @for (user of page().items; track user.id) {
                <tr>
                  <td>
                    <a [routerLink]="['/admin/users', user.id]">{{ user.email }}</a>
                    @if (!user.emailVerified) {
                      <span class="chip">unverified</span>
                    }
                    @if (locked(user)) {
                      <app-badge label="Locked" tone="danger" />
                    }
                  </td>
                  <td><app-badge [label]="user.status" [tone]="tone(user.status)" /></td>
                  <td>
                    @for (role of user.roles; track role) {
                      <span class="chip">{{ role }}</span>
                    } @empty {
                      <span class="muted">—</span>
                    }
                  </td>
                  <td class="time">{{ user.createdAt | instant: 'date' }}</td>
                  <td class="time">{{ user.lastLoginAt | instant }}</td>
                  <td>
                    <div class="row-actions">
                      <a class="btn btn--sm" [routerLink]="['/admin/users', user.id]">Manage</a>
                    </div>
                  </td>
                </tr>
              }
            </tbody>
          </table>
        </div>

        <app-paginator
          [page]="page().page"
          [size]="page().size"
          [totalElements]="page().totalElements"
          [totalPages]="page().totalPages"
          (goTo)="reload($event)"
        />
      }
    </section>
  `,
  styles: `
    .create-grid { display: grid; gap: 0 1rem; grid-template-columns: repeat(auto-fit, minmax(16rem, 1fr)); }
    .roles { border: 1px solid var(--border); border-radius: 8px; padding: 0.75rem; margin: 1rem 0 0; display: grid; gap: 0.3rem; }
    .rules { list-style: none; margin: 0; padding: 0; display: grid; gap: 0.15rem; font-size: 0.78rem; color: var(--fg-muted); }
    .rules li { display: flex; gap: 0.45rem; }
    .rules__met { color: var(--ok-fg); }
  `,
})
export class UserListComponent {
  private readonly api = inject(UsersApi);
  private readonly rolesApi = inject(RolesApi);
  private readonly fb = inject(FormBuilder);
  private readonly notifications = inject(NotificationsService);
  private readonly auth = inject(AuthService);

  protected readonly statuses = USER_STATUSES;
  protected readonly rules = PASSWORD_RULES;
  protected readonly tone = userStatusTone;
  protected readonly locked = (user: UserResponse) => isLockedNow(user.lockedUntil);

  protected readonly query = signal('');
  protected readonly status = signal<UserStatus | ''>('');
  protected readonly loading = signal(true);
  protected readonly busy = signal(false);
  protected readonly creating = signal(false);
  protected readonly roles = signal<RoleResponse[]>([]);
  protected readonly selectedRoles = signal<ReadonlySet<string>>(new Set());

  protected readonly page = signal<PageResponse<UserResponse>>({
    items: [],
    page: 0,
    size: PAGE_SIZE,
    totalElements: 0,
    totalPages: 0,
  });

  protected readonly canCreate = () => this.auth.has('USER_CREATE');

  protected readonly createForm = this.fb.nonNullable.group({
    email: ['', [Validators.required, Validators.email]],
    password: ['', [Validators.required, passwordPolicyValidator()]],
    emailVerified: [false],
  });

  constructor() {
    this.reload(0);
    // Only needed to populate the create form; a reader without ROLE_READ simply
    // gets no role checkboxes rather than an error they cannot act on.
    if (this.auth.has('ROLE_READ')) {
      this.rolesApi.list().subscribe((roles) => this.roles.set(roles));
    }
  }

  protected onStatus(value: string): void {
    this.status.set((value || '') as UserStatus | '');
    this.reload(0);
  }

  protected toggleRole(id: string): void {
    this.selectedRoles.update((current) => {
      const next = new Set(current);
      if (!next.delete(id)) {
        next.add(id);
      }
      return next;
    });
  }

  protected reload(page: number): void {
    this.loading.set(true);
    this.api
      .search(
        { query: this.query() || undefined, status: this.status() || undefined },
        { page, size: PAGE_SIZE },
      )
      .subscribe({
        next: (result) => {
          this.page.set(result);
          this.loading.set(false);
        },
        error: () => this.loading.set(false),
      });
  }

  protected create(): void {
    if (this.createForm.invalid || this.busy()) {
      this.createForm.markAllAsTouched();
      return;
    }
    this.busy.set(true);
    const { email, password, emailVerified } = this.createForm.getRawValue();

    this.api
      .create({ email, password, emailVerified, roleIds: [...this.selectedRoles()] })
      .subscribe({
        next: (user) => {
          this.busy.set(false);
          this.creating.set(false);
          this.createForm.reset({ emailVerified: false });
          this.selectedRoles.set(new Set());
          this.notifications.success('Created ' + user.email + '.');
          this.reload(0);
        },
        error: () => this.busy.set(false),
      });
  }
}
