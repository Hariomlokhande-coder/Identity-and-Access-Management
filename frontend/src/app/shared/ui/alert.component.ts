import { ChangeDetectionStrategy, Component, input } from '@angular/core';

/** An inline message attached to the thing that failed, rather than a floating toast. */
@Component({
  selector: 'app-alert',
  changeDetection: ChangeDetectionStrategy.OnPush,
  template: `
    @if (text()) {
      <div class="alert" [class]="'alert--' + kind()" role="alert">
        <span class="alert__icon" aria-hidden="true">
          @switch (kind()) {
            @case ('success') {
              <svg viewBox="0 0 20 20" fill="none" stroke="currentColor" stroke-width="1.9" stroke-linecap="round" stroke-linejoin="round">
                <circle cx="10" cy="10" r="7.5" />
                <path d="m6.8 10.2 2.1 2.1 4.3-4.4" />
              </svg>
            }
            @case ('info') {
              <svg viewBox="0 0 20 20" fill="none" stroke="currentColor" stroke-width="1.9" stroke-linecap="round">
                <circle cx="10" cy="10" r="7.5" />
                <path d="M10 9.2v4.2M10 6.6h.01" />
              </svg>
            }
            @default {
              <svg viewBox="0 0 20 20" fill="none" stroke="currentColor" stroke-width="1.9" stroke-linecap="round">
                <circle cx="10" cy="10" r="7.5" />
                <path d="M10 6.4v4.4M10 13.6h.01" />
              </svg>
            }
          }
        </span>

        <span class="alert__body">
          <span class="alert__text">{{ text() }}</span>
          @if (correlationId(); as id) {
            <span class="alert__ref" title="Quote this when reporting the problem">{{ id }}</span>
          }
        </span>
      </div>
    }
  `,
  styles: `
    .alert {
      display: flex;
      align-items: flex-start;
      gap: 0.6rem;
      padding: 0.7rem 0.85rem;
      border-radius: var(--r-sm);
      border: 1px solid;
      font-size: 0.855rem;
      line-height: 1.5;
      animation: rise 180ms var(--ease) both;
    }
    .alert__icon { flex: none; display: grid; place-items: center; margin-top: 0.08rem; }
    .alert__icon svg { width: 1rem; height: 1rem; }
    .alert__body { display: grid; gap: 0.25rem; min-width: 0; }
    .alert__ref {
      font-family: var(--font-mono);
      font-size: 0.68rem;
      opacity: 0.7;
      overflow-wrap: anywhere;
    }
    .alert--error { background: var(--danger-bg); border-color: var(--danger-border); color: var(--danger-fg); }
    .alert--success { background: var(--ok-bg); border-color: var(--ok-border); color: var(--ok-fg); }
    .alert--info { background: var(--info-bg); border-color: var(--info-border); color: var(--info-fg); }
  `,
})
export class AlertComponent {
  readonly text = input<string | null>(null);
  readonly kind = input<'error' | 'success' | 'info'>('error');
  readonly correlationId = input<string | null>(null);
}
