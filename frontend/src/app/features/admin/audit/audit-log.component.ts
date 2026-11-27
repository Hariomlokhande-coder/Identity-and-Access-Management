import { ChangeDetectionStrategy, Component, inject, signal } from '@angular/core';
import { FormsModule } from '@angular/forms';
import { RouterLink } from '@angular/router';
import { AuditApi } from '../../../core/api/audit.api';
import { AUDIT_EVENT_TYPES, AuditEventResponse, AuditEventType } from '../../../core/models/audit';
import { PageResponse } from '../../../core/models/common';
import { InstantPipe, OrDashPipe, ShortIdPipe, auditTone } from '../../../shared/format';
import { BadgeComponent } from '../../../shared/ui/badge.component';
import { PaginatorComponent } from '../../../shared/ui/paginator.component';

const PAGE_SIZE = 50;

/**
 * The security event log, newest first.
 *
 * The correlation id is shown because it is the join key between this table and the
 * server logs: an event here and the request that caused it carry the same one.
 */
@Component({
  selector: 'app-audit-log',
  changeDetection: ChangeDetectionStrategy.OnPush,
  imports: [
    FormsModule,
    RouterLink,
    BadgeComponent,
    PaginatorComponent,
    InstantPipe,
    OrDashPipe,
    ShortIdPipe,
  ],
  template: `
    <div class="page-header">
      <div>
        <h1>Audit log</h1>
        <p class="page-header__subtitle">
          Security-relevant events, newest first. Read-only - entries are never edited
          or removed from here.
        </p>
      </div>
    </div>

    <section class="card">
      <div class="toolbar">
        <label class="field">
          <span class="field__label">Event type</span>
          <select [ngModel]="eventType()" (ngModelChange)="onEventType($event)" name="eventType">
            <option value="">Any</option>
            @for (type of eventTypes; track type) {
              <option [value]="type">{{ type }}</option>
            }
          </select>
        </label>
        <label class="field" style="flex: 1 1 20rem">
          <span class="field__label">Actor user id</span>
          <input
            type="search"
            placeholder="UUID"
            [ngModel]="actorUserId()"
            (ngModelChange)="actorUserId.set($event)"
            (keyup.enter)="reload(0)"
            name="actor"
          />
        </label>
        <button type="button" class="btn" (click)="reload(0)">Apply</button>
        @if (eventType() || actorUserId()) {
          <button type="button" class="btn btn--ghost" (click)="clear()">Clear</button>
        }
      </div>

      @if (loading()) {
        <p class="muted">Loading…</p>
      } @else if (page().items.length === 0) {
        <p class="empty">No events match this filter.</p>
      } @else {
        <div class="table-wrap">
          <table class="data">
            <thead>
              <tr>
                <th class="time">When</th>
                <th>Event</th>
                <th>Actor</th>
                <th>Target</th>
                <th>Application</th>
                <th>IP</th>
                <th>Detail</th>
              </tr>
            </thead>
            <tbody>
              @for (event of page().items; track event.id) {
                <tr>
                  <td class="time">{{ event.createdAt | instant }}</td>
                  <td>
                    <app-badge [label]="event.eventType" [tone]="tone(event)" />
                    @if (event.outcome === 'FAILURE') {
                      <span class="chip">failed</span>
                    }
                  </td>
                  <td class="mono">
                    @if (event.actorUserId; as actor) {
                      <a [routerLink]="['/admin/users', actor]" [title]="actor">{{ actor | shortId }}</a>
                    } @else {
                      <span class="muted">—</span>
                    }
                  </td>
                  <td class="mono target" [title]="event.targetId ?? ''">
                    {{ event.targetId | shortId: 22 }}
                  </td>
                  <td>{{ event.clientId | orDash }}</td>
                  <td class="mono">{{ event.ipAddress | orDash }}</td>
                  <td class="detail">
                    {{ event.detail | orDash }}
                    @if (event.correlationId; as id) {
                      <span class="corr mono" [title]="'Correlation id ' + id">{{ id | shortId }}</span>
                    }
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
    .detail { max-width: 24rem; }
    .target { max-width: 14rem; overflow: hidden; text-overflow: ellipsis; white-space: nowrap; }
    .corr {
      display: block;
      margin-top: 0.15rem;
      font-size: 0.68rem;
      color: var(--fg-subtle);
      white-space: nowrap;
    }
  `,
})
export class AuditLogComponent {
  private readonly api = inject(AuditApi);

  protected readonly eventTypes = AUDIT_EVENT_TYPES;
  protected readonly eventType = signal<AuditEventType | ''>('');
  protected readonly actorUserId = signal('');
  protected readonly loading = signal(true);

  protected readonly page = signal<PageResponse<AuditEventResponse>>({
    items: [],
    page: 0,
    size: PAGE_SIZE,
    totalElements: 0,
    totalPages: 0,
  });

  protected readonly tone = (event: AuditEventResponse) => auditTone(event.eventType, event.outcome);

  constructor() {
    this.reload(0);
  }

  protected onEventType(value: string): void {
    this.eventType.set((value || '') as AuditEventType | '');
    this.reload(0);
  }

  protected clear(): void {
    this.eventType.set('');
    this.actorUserId.set('');
    this.reload(0);
  }

  protected reload(page: number): void {
    this.loading.set(true);
    this.api
      .events(
        {
          eventType: this.eventType() || undefined,
          actorUserId: this.actorUserId().trim() || undefined,
        },
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
}
