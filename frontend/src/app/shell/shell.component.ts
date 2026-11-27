import { ChangeDetectionStrategy, Component, computed, inject, signal } from '@angular/core';
import { Router, RouterLink, RouterLinkActive, RouterOutlet } from '@angular/router';
import { UsersApi } from '../core/api/users.api';
import { AuthService } from '../core/auth/auth.service';
import { Permission } from '../core/models/auth';

interface NavItem {
  label: string;
  path: string;
  /** Shown only when the user holds at least one of these. Empty means always. */
  requires: Permission[];
}

interface NavGroup {
  title: string;
  items: NavItem[];
}

const NAV: NavGroup[] = [
  {
    title: 'Account',
    items: [
      { label: 'Profile', path: '/account/profile', requires: [] },
      { label: 'Security', path: '/account/security', requires: [] },
      { label: 'Devices', path: '/account/sessions', requires: [] },
      { label: 'Connected apps', path: '/account/apps', requires: [] },
    ],
  },
  {
    title: 'Administration',
    items: [
      { label: 'Users', path: '/admin/users', requires: ['USER_READ'] },
      { label: 'Roles', path: '/admin/roles', requires: ['ROLE_READ'] },
      { label: 'Applications', path: '/admin/clients', requires: ['CLIENT_READ'] },
      { label: 'Audit log', path: '/admin/audit', requires: ['AUDIT_READ'] },
    ],
  },
];

/**
 * The signed-in frame: navigation on the left, the routed screen on the right.
 *
 * Navigation is filtered by the permissions in the access token. This is purely so
 * the console does not advertise screens that would 403 - the server enforces the
 * same permissions on every request behind them.
 */
@Component({
  selector: 'app-shell',
  changeDetection: ChangeDetectionStrategy.OnPush,
  imports: [RouterOutlet, RouterLink, RouterLinkActive],
  template: `
    <div class="shell">
      <aside class="sidebar">
        <div class="brand">
          <span class="brand__mark" aria-hidden="true">
            <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
              <path d="M12 2 4 6v6c0 5 3.4 9.1 8 10 4.6-.9 8-5 8-10V6l-8-4Z" stroke-linejoin="round" />
              <circle cx="12" cy="11" r="2.4" />
              <path d="M12 13.4V17" stroke-linecap="round" />
            </svg>
          </span>
          <span class="brand__text">
            <span class="brand__name">Identity</span>
            <span class="brand__sub">Access console</span>
          </span>
        </div>

        <nav class="nav">
          @for (group of visibleGroups(); track group.title) {
            <p class="nav__title">{{ group.title }}</p>
            <ul class="nav__list">
              @for (item of group.items; track item.path) {
                <li>
                  <a
                    class="nav__link"
                    [routerLink]="item.path"
                    routerLinkActive="nav__link--active"
                    ariaCurrentWhenActive="page"
                    [routerLinkActiveOptions]="{ exact: false }"
                    >{{ item.label }}</a
                  >
                </li>
              }
            </ul>
          }
        </nav>

        <div class="who">
          <span class="who__avatar" aria-hidden="true">{{ initials() }}</span>
          <span class="who__text">
            <span class="who__name" [title]="email() ?? userId() ?? ''">{{ displayName() }}</span>
            @if (roles().length) {
              <span class="who__roles" [title]="roles().join(', ')">{{ roles().join(' · ') }}</span>
            }
          </span>
          <button type="button" class="who__out" (click)="signOut()" title="Sign out" aria-label="Sign out">
            <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round">
              <path d="M15 17l5-5-5-5M20 12H9M12 20H6a2 2 0 0 1-2-2V6a2 2 0 0 1 2-2h6" />
            </svg>
          </button>
        </div>
      </aside>

      <main class="content">
        <div class="content__inner">
          <router-outlet />
        </div>
      </main>
    </div>
  `,
  styles: `
    .shell {
      display: grid;
      grid-template-columns: 14rem minmax(0, 1fr);
      min-height: 100vh;
    }

    /* ---- Sidebar ---- */

    .sidebar {
      display: flex;
      flex-direction: column;
      gap: 1.5rem;
      padding: 1.6rem 1rem 1rem;
      background: var(--surface);
      border-right: 1px solid var(--border);
      position: sticky;
      top: 0;
      height: 100vh;
      overflow-y: auto;
    }

    .brand { display: flex; align-items: center; gap: 0.65rem; padding: 0 0.35rem; }
    .brand__mark {
      display: grid;
      place-items: center;
      width: 2rem;
      height: 2rem;
      flex: none;
      border-radius: var(--r-sm);
      background: var(--accent);
      color: var(--accent-fg);
    }
    .brand__mark svg { width: 1.05rem; height: 1.05rem; }
    .brand__text { display: grid; line-height: 1.25; }
    .brand__name {
      font-family: var(--font-display);
      font-weight: 650;
      font-size: 0.93rem;
      letter-spacing: -0.015em;
    }
    .brand__sub { font-size: 0.7rem; color: var(--fg-subtle); }

    .nav { flex: 1; }
    .nav__title {
      margin: 1.1rem 0 0.4rem;
      padding: 0 0.55rem;
      font-size: 0.66rem;
      font-weight: 650;
      text-transform: uppercase;
      letter-spacing: 0.09em;
      color: var(--fg-subtle);
    }
    .nav__title:first-child { margin-top: 0; }

    .nav__list { list-style: none; margin: 0; padding: 0; display: grid; gap: 2px; }

    /* The active item gets an accent rail rather than only a tint, so the current
       screen is findable at a glance without relying on colour alone. */
    .nav__link {
      display: block;
      position: relative;
      padding: 0.42rem 0.6rem;
      border-radius: var(--r-sm);
      color: var(--fg-muted);
      text-decoration: none;
      font-size: 0.86rem;
      font-weight: 500;
    }
    .nav__link:hover { background: var(--chip-bg); color: var(--fg); }

    .nav__link--active {
      background: var(--accent-soft);
      color: var(--accent);
      font-weight: 600;
    }
    .nav__link--active::before {
      content: '';
      position: absolute;
      left: 0;
      top: 50%;
      translate: 0 -50%;
      width: 3px;
      height: 1.1rem;
      border-radius: 0 3px 3px 0;
      background: var(--accent);
    }

    /* ---- Who is signed in ---- */

    .who {
      display: flex;
      align-items: center;
      gap: 0.6rem;
      padding: 0.8rem 0.15rem;
      border-top: 1px solid var(--border);
    }
    .who__avatar {
      display: grid;
      place-items: center;
      width: 1.9rem;
      height: 1.9rem;
      flex: none;
      border-radius: var(--r-full);
      background: var(--accent);
      color: var(--accent-fg);
      font-size: 0.7rem;
      font-weight: 650;
      letter-spacing: 0.02em;
    }
    .who__text { display: grid; min-width: 0; flex: 1; line-height: 1.3; }
    .who__name {
      font-size: 0.79rem;
      font-weight: 600;
      overflow: hidden;
      text-overflow: ellipsis;
      white-space: nowrap;
    }
    .who__roles {
      font-size: 0.68rem;
      color: var(--fg-subtle);
      overflow: hidden;
      text-overflow: ellipsis;
      white-space: nowrap;
    }
    .who__out {
      display: grid;
      place-items: center;
      flex: none;
      width: 1.7rem;
      height: 1.7rem;
      padding: 0;
      border: 0;
      border-radius: var(--r-sm);
      background: none;
      color: var(--fg-subtle);
      cursor: pointer;
    }
    .who__out svg { width: 0.95rem; height: 0.95rem; }
    .who__out:hover { background: var(--danger-bg); color: var(--danger-fg); }

    /* ---- Content ---- */

    .content { min-width: 0; }
    .content__inner {
      padding: 2.75rem clamp(1.5rem, 4vw, 4rem) 4rem;
      max-width: 1160px;
      animation: rise 220ms var(--ease) both;
    }

    @media (max-width: 860px) {
      .shell { grid-template-columns: 1fr; }
      .sidebar {
        position: static;
        height: auto;
        border-right: 0;
        border-bottom: 1px solid var(--border);
        gap: 1rem;
      }
      .nav__list { display: flex; flex-wrap: wrap; }
      .content__inner { padding: 1.35rem 1.1rem 3rem; }
    }
  `,
})
export class ShellComponent {
  private readonly auth = inject(AuthService);
  private readonly users = inject(UsersApi);
  private readonly router = inject(Router);

  protected readonly roles = this.auth.roles;
  protected readonly userId = this.auth.userId;

  /**
   * The access token carries no email claim, so the address is fetched once. Until
   * it arrives the subject stands in - better a short id than an empty slot that
   * shifts the layout when it fills.
   */
  protected readonly email = signal<string | null>(null);

  protected readonly displayName = computed(() => {
    const email = this.email();
    if (email) {
      return email;
    }
    const id = this.auth.userId();
    return id ? id.slice(0, 8) + '…' : 'Signed in';
  });

  protected readonly initials = computed(() => {
    const email = this.email();
    if (email) {
      const [local] = email.split('@');
      const parts = local.split(/[._-]+/).filter(Boolean);
      const letters = parts.length > 1 ? parts[0][0] + parts[1][0] : local.slice(0, 2);
      return letters.toUpperCase();
    }
    return (this.auth.userId() ?? '··').slice(0, 2).toUpperCase();
  });

  protected readonly visibleGroups = computed(() =>
    NAV.map((group) => ({
      ...group,
      items: group.items.filter(
        (item) => item.requires.length === 0 || this.auth.hasAny(...item.requires),
      ),
    })).filter((group) => group.items.length > 0),
  );

  constructor() {
    this.users.me().subscribe({
      next: (me) => this.email.set(me.email),
      // The name is decoration; a failure here must not interrupt the console.
      error: () => undefined,
    });
  }

  protected signOut(): void {
    this.auth.logout().subscribe(() => void this.router.navigate(['/login']));
  }
}
