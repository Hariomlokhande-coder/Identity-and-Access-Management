import { ChangeDetectionStrategy, Component, input } from '@angular/core';

/**
 * The frame around every unauthenticated screen.
 *
 * These screens are the identity provider's own UI - the pages iam.login-url and
 * iam.consent-url point at - so they deliberately carry no console navigation. A
 * user redirected here mid-OAuth flow is not "in" the console yet.
 */
@Component({
  selector: 'app-auth-card',
  changeDetection: ChangeDetectionStrategy.OnPush,
  template: `
    <main class="stage">
      <div class="layout">
        <div class="auth__brand">
          <span class="auth__mark" aria-hidden="true">
            <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
              <path d="M12 2 4 6v6c0 5 3.4 9.1 8 10 4.6-.9 8-5 8-10V6l-8-4Z" stroke-linejoin="round" />
              <circle cx="12" cy="11" r="2.4" />
              <path d="M12 13.4V17" stroke-linecap="round" />
            </svg>
          </span>
          <span class="auth__wordmark">Identity</span>
        </div>

        <div class="stack">
          <div class="auth">
            <h1 class="auth__title">{{ heading() }}</h1>
            @if (subheading(); as sub) {
              <p class="auth__sub">{{ sub }}</p>
            }

            <ng-content />
          </div>
          <ng-content select="[footer]" />
        </div>
      </div>
    </main>
  `,
  styles: `
    .stage {
      display: grid;
      align-items: center;
      min-height: 100vh;
      padding: clamp(1rem, 6vw, 5rem);
    }

    .layout {
      width: min(100%, 56rem);
      margin-inline: auto;
      display: grid;
      grid-template-columns: minmax(11rem, 2fr) minmax(0, 3fr);
      gap: clamp(2rem, 7vw, 6rem);
      align-items: start;
    }

    .stack {
      min-width: 0;
      display: grid;
      gap: 0.9rem;
      animation: rise 200ms var(--ease) both;
    }

    .auth {
      padding: clamp(1.15rem, 4vw, 2.5rem);
      background: var(--surface);
      border: 1px solid var(--border);
      border-top: 3px solid var(--accent);
      border-radius: var(--r-md);
    }

    .auth__brand {
      display: flex;
      align-items: center;
      gap: 0.75rem;
      border-top: 1px solid var(--border);
      padding-top: 1.15rem;
    }

    .auth__mark {
      display: grid;
      place-items: center;
      width: 1.85rem;
      height: 1.85rem;
      border-radius: var(--r-sm);
      background: var(--accent);
      color: var(--accent-fg);
    }
    .auth__mark svg { width: 1rem; height: 1rem; }
    .auth__wordmark {
      font-family: var(--font-display);
      font-weight: 650;
      font-size: 1.65rem;
      letter-spacing: -0.012em;
    }

    .auth__title { margin: 0 0 0.5rem; }
    .auth__sub {
      margin: 0 0 1.4rem;
      color: var(--fg-muted);
      font-size: 0.865rem;
      line-height: 1.55;
    }
    @media (max-width: 620px) {
      .layout { grid-template-columns: minmax(0, 1fr); gap: 1.25rem; max-width: 31rem; }
      .auth__brand { padding-top: 0.8rem; }
    }
  `,
})
export class AuthCardComponent {
  readonly heading = input.required<string>();
  readonly subheading = input<string | null>(null);
}
