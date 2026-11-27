import { ChangeDetectionStrategy, Component, inject } from '@angular/core';
import { RouterLink } from '@angular/router';
import { AuthService } from '../core/auth/auth.service';

/** Where permissionGuard sends a signed-in user who lacks the permission. */
@Component({
  selector: 'app-forbidden',
  changeDetection: ChangeDetectionStrategy.OnPush,
  imports: [RouterLink],
  template: `
    <div class="page-header">
      <div>
        <h1>Not allowed</h1>
        <p class="page-header__subtitle">
          Your account does not hold the permission that screen requires.
        </p>
      </div>
    </div>

    <section class="card">
      <p class="muted" style="font-size: 0.87rem">
        Permissions come from the roles assigned to your account. An administrator can
        change them; they take effect on your next token refresh, without you signing
        out.
      </p>

      <p class="label">Your roles</p>
      <p>
        @for (role of roles(); track role) {
          <span class="chip">{{ role }}</span>
        } @empty {
          <span class="muted">None</span>
        }
      </p>

      <p class="label">Your permissions</p>
      <p>
        @for (permission of permissions(); track permission) {
          <span class="chip">{{ permission }}</span>
        } @empty {
          <span class="muted">None</span>
        }
      </p>

      <p class="mt-3"><a routerLink="/account/profile">Back to your profile</a></p>
    </section>
  `,
  styles: `
    .label { margin: 1.2rem 0 0.3rem; font-size: 0.76rem; color: var(--fg-muted); }
  `,
})
export class ForbiddenComponent {
  private readonly auth = inject(AuthService);

  protected readonly roles = this.auth.roles;
  protected readonly permissions = () => [...this.auth.permissions()].sort();
}
