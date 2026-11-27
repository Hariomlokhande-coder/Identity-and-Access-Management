import { ChangeDetectionStrategy, Component, inject, signal } from '@angular/core';
import { FormBuilder, ReactiveFormsModule, Validators } from '@angular/forms';
import { UsersApi } from '../../core/api/users.api';
import { NotificationsService } from '../../core/notifications.service';
import { UserResponse } from '../../core/models/user';
import { InstantPipe, userStatusTone } from '../../shared/format';
import { BadgeComponent } from '../../shared/ui/badge.component';

/** The signed-in user's own record, and the one field they can change themselves. */
@Component({
  selector: 'app-profile',
  changeDetection: ChangeDetectionStrategy.OnPush,
  imports: [ReactiveFormsModule, BadgeComponent, InstantPipe],
  template: `
    <div class="page-header">
      <div>
        <h1>Profile</h1>
        <p class="page-header__subtitle">Your account as the platform sees it.</p>
      </div>
    </div>

    @if (user(); as me) {
      <section class="card">
        <dl class="facts">
          <div>
            <dt>Email</dt>
            <dd>{{ me.email }}</dd>
          </div>
          <div>
            <dt>Status</dt>
            <dd>
              <app-badge [label]="me.status" [tone]="tone(me)" />
              @if (!me.emailVerified) {
                <span class="muted" style="margin-left: 0.5rem; font-size: 0.8rem">
                  Email not verified
                </span>
              }
            </dd>
          </div>
          <div>
            <dt>Roles</dt>
            <dd>
              @for (role of me.roles; track role) {
                <span class="chip">{{ role }}</span>
              } @empty {
                <span class="muted">None</span>
              }
            </dd>
          </div>
          <div>
            <dt>Member since</dt>
            <dd>{{ me.createdAt | instant }}</dd>
          </div>
          <div>
            <dt>Last sign-in</dt>
            <dd>{{ me.lastLoginAt | instant }}</dd>
          </div>
          <div>
            <dt>User id</dt>
            <dd class="mono">{{ me.id }}</dd>
          </div>
        </dl>
      </section>

      <section class="card mt-3">
        <h2>Change your email address</h2>
        <p class="field__hint" style="margin-bottom: 1rem">
          A new address has to be verified before it can be used to sign in.
        </p>
        <form [formGroup]="form" (ngSubmit)="save()" novalidate class="email-form">
          <label class="field">
            <span class="field__label">New email</span>
            <input type="email" formControlName="email" autocomplete="email" />
          </label>
          <button type="submit" class="btn btn--primary" [disabled]="busy() || form.invalid">
            {{ busy() ? 'Saving…' : 'Update email' }}
          </button>
        </form>
      </section>
    } @else if (loading()) {
      <p class="muted">Loading…</p>
    }
  `,
  styles: `
    .facts { margin: 0; display: grid; gap: 0.9rem; }
    .facts > div { display: grid; grid-template-columns: 150px 1fr; gap: 1rem; align-items: baseline; }
    dt { color: var(--fg-muted); font-size: 0.8rem; }
    dd { margin: 0; overflow-wrap: anywhere; }
    .email-form { display: flex; gap: 0.75rem; align-items: flex-end; flex-wrap: wrap; }
    .email-form .field { margin-bottom: 0; flex: 1 1 18rem; }
    @media (max-width: 560px) {
      .facts > div { grid-template-columns: 1fr; gap: 0.15rem; }
    }
  `,
})
export class ProfileComponent {
  private readonly api = inject(UsersApi);
  private readonly fb = inject(FormBuilder);
  private readonly notifications = inject(NotificationsService);

  protected readonly user = signal<UserResponse | null>(null);
  protected readonly loading = signal(true);
  protected readonly busy = signal(false);
  protected readonly tone = (user: UserResponse) => userStatusTone(user.status);

  protected readonly form = this.fb.nonNullable.group({
    email: ['', [Validators.required, Validators.email]],
  });

  constructor() {
    this.load();
  }

  private load(): void {
    this.api.me().subscribe({
      next: (me) => {
        this.user.set(me);
        this.form.controls.email.setValue(me.email);
        this.loading.set(false);
      },
      error: () => this.loading.set(false),
    });
  }

  protected save(): void {
    if (this.form.invalid || this.busy()) {
      return;
    }
    const email = this.form.controls.email.value;
    if (email === this.user()?.email) {
      this.notifications.info('That is already your email address.');
      return;
    }
    this.busy.set(true);
    this.api.updateOwnEmail({ email }).subscribe({
      next: (updated) => {
        this.busy.set(false);
        this.user.set(updated);
        this.notifications.success('Email updated. Check the new address for a verification link.');
      },
      error: () => this.busy.set(false),
    });
  }
}
