import { ChangeDetectionStrategy, Component, computed, input, output } from '@angular/core';

/** Page controls for any endpoint that returns a PageResponse. */
@Component({
  selector: 'app-paginator',
  changeDetection: ChangeDetectionStrategy.OnPush,
  template: `
    <div class="paginator">
      <span class="paginator__count">
        @if (totalElements() === 0) {
          Nothing to show
        } @else {
          <strong>{{ firstItem() }}&ndash;{{ lastItem() }}</strong> of {{ totalElements() }}
        }
      </span>

      <div class="paginator__buttons">
        <button
          type="button"
          class="btn btn--ghost btn--sm"
          [disabled]="page() === 0"
          (click)="goTo.emit(page() - 1)"
        >
          <svg viewBox="0 0 16 16" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round">
            <path d="M9.5 4 5.5 8l4 4" />
          </svg>
          Previous
        </button>

        <span class="paginator__page">{{ page() + 1 }} / {{ displayTotalPages() }}</span>

        <button
          type="button"
          class="btn btn--ghost btn--sm"
          [disabled]="page() + 1 >= totalPages()"
          (click)="goTo.emit(page() + 1)"
        >
          Next
          <svg viewBox="0 0 16 16" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round">
            <path d="M6.5 4l4 4-4 4" />
          </svg>
        </button>
      </div>
    </div>
  `,
  styles: `
    .paginator {
      display: flex;
      align-items: center;
      justify-content: space-between;
      gap: 1rem;
      flex-wrap: wrap;
      margin-top: 0.9rem;
      padding-top: 0.9rem;
      border-top: 1px solid var(--border);
      font-size: 0.8rem;
      color: var(--fg-muted);
    }
    .paginator__count strong { color: var(--fg); font-weight: 600; }
    .paginator__buttons { display: flex; align-items: center; gap: 0.5rem; }
    .paginator__buttons svg { width: 0.75rem; height: 0.75rem; }
    .paginator__page {
      font-family: var(--font-mono);
      font-size: 0.75rem;
      color: var(--fg-subtle);
      padding: 0 0.15rem;
    }
  `,
})
export class PaginatorComponent {
  readonly page = input.required<number>();
  readonly size = input.required<number>();
  readonly totalElements = input.required<number>();
  readonly totalPages = input.required<number>();

  readonly goTo = output<number>();

  /** An empty result still reads as "1 / 1" rather than "1 / 0". */
  protected readonly displayTotalPages = computed(() => Math.max(1, this.totalPages()));
  protected readonly firstItem = computed(() => this.page() * this.size() + 1);
  protected readonly lastItem = computed(() =>
    Math.min(this.totalElements(), (this.page() + 1) * this.size()),
  );
}
