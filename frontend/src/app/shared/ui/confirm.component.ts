import { ChangeDetectionStrategy, Component, inject } from '@angular/core';
import { ConfirmService } from './confirm.service';

/** The dialog half of ConfirmService. Mounted once, in the app shell. */
@Component({
  selector: 'app-confirm',
  changeDetection: ChangeDetectionStrategy.OnPush,
  template: `
    @if (confirm.current(); as request) {
      <div class="backdrop" (click)="confirm.answer(false)">
        <div
          class="dialog"
          role="alertdialog"
          aria-modal="true"
          [attr.aria-label]="request.title"
          (click)="$event.stopPropagation()"
        >
          <span class="dialog__icon" [class.dialog__icon--danger]="request.destructive" aria-hidden="true">
            <svg viewBox="0 0 20 20" fill="none" stroke="currentColor" stroke-width="1.9" stroke-linecap="round">
              <path d="M10 6.4v4.4M10 13.6h.01" />
              <circle cx="10" cy="10" r="7.5" />
            </svg>
          </span>

          <h2 class="dialog__title">{{ request.title }}</h2>
          <p class="dialog__message">{{ request.message }}</p>

          <div class="dialog__actions">
            <button type="button" class="btn btn--ghost" (click)="confirm.answer(false)">Cancel</button>
            <button
              type="button"
              class="btn"
              [class.btn--danger]="request.destructive"
              [class.btn--primary]="!request.destructive"
              (click)="confirm.answer(true)"
            >
              {{ request.confirmLabel ?? 'Confirm' }}
            </button>
          </div>
        </div>
      </div>
    }
  `,
  styles: `
    .backdrop {
      position: fixed;
      inset: 0;
      z-index: 200;
      display: grid;
      place-items: center;
      padding: 1rem;
      background: var(--scrim);
      animation: fade 140ms var(--ease) both;
    }
    @keyframes fade { from { opacity: 0; } to { opacity: 1; } }

    .dialog {
      width: min(27rem, 100%);
      background: var(--surface);
      border: 1px solid var(--border);
      border-radius: var(--r-lg);
      padding: 1.4rem;
      animation: pop 180ms var(--ease) both;
    }
    @keyframes pop {
      from { opacity: 0; transform: translateY(10px) scale(0.97); }
      to { opacity: 1; transform: none; }
    }

    .dialog__icon {
      display: grid;
      place-items: center;
      width: 2.1rem;
      height: 2.1rem;
      margin-bottom: 0.9rem;
      border-radius: var(--r-full);
      background: var(--info-bg);
      color: var(--info-fg);
    }
    .dialog__icon--danger { background: var(--danger-bg); color: var(--danger-fg); }
    .dialog__icon svg { width: 1.05rem; height: 1.05rem; }

    .dialog__title { margin: 0 0 0.4rem; font-size: 1.02rem; }
    .dialog__message {
      margin: 0 0 1.35rem;
      color: var(--fg-muted);
      font-size: 0.875rem;
      line-height: 1.55;
    }
    .dialog__actions { display: flex; justify-content: flex-end; gap: 0.55rem; }
  `,
})
export class ConfirmComponent {
  protected readonly confirm = inject(ConfirmService);
}
