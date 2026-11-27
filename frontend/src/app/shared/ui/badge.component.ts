import { ChangeDetectionStrategy, Component, computed, input } from '@angular/core';

export type BadgeTone = 'neutral' | 'ok' | 'warn' | 'danger';

/**
 * A status pill. The tone is passed in rather than inferred from the label, so the
 * same component works for user status, client status and audit outcome without
 * knowing about any of them.
 *
 * The dot is not decoration: it carries the state at a glance and keeps the badge
 * readable for anyone who cannot separate the tint colours.
 */
@Component({
  selector: 'app-badge',
  changeDetection: ChangeDetectionStrategy.OnPush,
  template: `
    <span class="badge" [class]="'badge--' + tone()">
      <span class="badge__dot" aria-hidden="true"></span>
      {{ display() }}
    </span>
  `,
  styles: `
    .badge {
      display: inline-flex;
      align-items: center;
      gap: 0.35rem;
      padding: 0.16rem 0.55rem 0.16rem 0.45rem;
      margin: 0.1rem 0.15rem 0.1rem 0;
      border-radius: var(--r-full);
      font-size: 0.715rem;
      font-weight: 600;
      letter-spacing: -0.004em;
      line-height: 1.45;
      border: 1px solid;
      white-space: nowrap;
      vertical-align: middle;
    }
    .badge__dot {
      width: 5px;
      height: 5px;
      flex: none;
      border-radius: var(--r-full);
      background: currentColor;
    }
    .badge--neutral { background: var(--chip-bg); border-color: var(--border); color: var(--fg-muted); }
    .badge--ok { background: var(--ok-bg); border-color: var(--ok-border); color: var(--ok-fg); }
    .badge--warn { background: var(--warn-bg); border-color: var(--warn-border); color: var(--warn-fg); }
    .badge--danger { background: var(--danger-bg); border-color: var(--danger-border); color: var(--danger-fg); }

    .badge--ok .badge__dot { background: var(--ok-dot); }
    .badge--warn .badge__dot { background: var(--warn-dot); }
    .badge--danger .badge__dot { background: var(--danger-dot); }
  `,
})
export class BadgeComponent {
  readonly label = input.required<string>();
  readonly tone = input<BadgeTone>('neutral');

  /** PENDING_VERIFICATION reads better as "Pending verification". */
  protected readonly display = computed(() => {
    const label = this.label();
    const words = label.replace(/_/g, ' ').toLowerCase();
    return words.charAt(0).toUpperCase() + words.slice(1);
  });
}
