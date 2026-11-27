import { ChangeDetectionStrategy, Component, inject } from '@angular/core';
import { NotificationsService } from '../../core/notifications.service';

/** Renders the global notice queue. Mounted once, in the app shell. */
@Component({
  selector: 'app-toasts',
  changeDetection: ChangeDetectionStrategy.OnPush,
  template: `
    <div class="toasts" aria-live="polite">
      @for (notice of notifications.notices(); track notice.id) {
        <div class="toast" [class]="'toast--' + notice.kind">
          <span class="toast__dot" aria-hidden="true"></span>
          <div class="toast__body">
            <p class="toast__text">{{ notice.text }}</p>
            @if (notice.correlationId; as id) {
              <p class="toast__ref">{{ id }}</p>
            }
          </div>
          <button type="button" class="toast__close" (click)="notifications.dismiss(notice.id)" aria-label="Dismiss">
            <svg viewBox="0 0 16 16" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round">
              <path d="m4.5 4.5 7 7M11.5 4.5l-7 7" />
            </svg>
          </button>
        </div>
      }
    </div>
  `,
  styles: `
    .toasts {
      position: fixed;
      right: 1.1rem;
      bottom: 1.1rem;
      z-index: 100;
      display: flex;
      flex-direction: column;
      gap: 0.55rem;
      max-width: min(26rem, calc(100vw - 2.2rem));
      pointer-events: none;
    }
    .toast {
      pointer-events: auto;
      display: flex;
      gap: 0.6rem;
      align-items: flex-start;
      padding: 0.7rem 0.8rem;
      border-radius: var(--r-md);
      border: 1px solid var(--border);
      background: var(--surface);
      font-size: 0.85rem;
      animation: toast-in 220ms var(--ease) both;
    }
    @keyframes toast-in {
      from { opacity: 0; transform: translateY(8px) scale(0.985); }
      to { opacity: 1; transform: none; }
    }

    /* The colour lives in a rail, not the whole panel: a notice reads as a message
       on the console's own surface rather than a coloured block. */
    .toast__dot {
      flex: none;
      width: 3px;
      align-self: stretch;
      border-radius: var(--r-full);
      background: var(--fg-subtle);
    }
    .toast--error .toast__dot { background: var(--danger-dot); }
    .toast--success .toast__dot { background: var(--ok-dot); }
    .toast--info .toast__dot { background: var(--info-dot); }

    .toast__body { flex: 1; min-width: 0; }
    .toast__text { margin: 0; line-height: 1.5; }
    .toast__ref {
      margin: 0.3rem 0 0;
      font-family: var(--font-mono);
      font-size: 0.68rem;
      color: var(--fg-subtle);
      overflow-wrap: anywhere;
    }
    .toast__close {
      flex: none;
      display: grid;
      place-items: center;
      width: 1.35rem;
      height: 1.35rem;
      padding: 0;
      border: 0;
      border-radius: 6px;
      background: none;
      color: var(--fg-subtle);
      cursor: pointer;
    }
    .toast__close svg { width: 0.75rem; height: 0.75rem; }
    .toast__close:hover { background: var(--chip-bg); color: var(--fg); }
  `,
})
export class ToastsComponent {
  protected readonly notifications = inject(NotificationsService);
}
