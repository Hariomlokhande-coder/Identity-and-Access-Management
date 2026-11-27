import { HttpClient } from '@angular/common/http';
import { Injectable, inject } from '@angular/core';
import { Observable } from 'rxjs';
import { AuditEventResponse, AuditEventType } from '../models/audit';
import { PageQuery, PageResponse } from '../models/common';
import { apiUrl, pageParams } from './api';

@Injectable({ providedIn: 'root' })
export class AuditApi {
  private readonly http = inject(HttpClient);

  /** Newest first, optionally narrowed to one actor or one event type. */
  events(
    filter: { eventType?: AuditEventType; actorUserId?: string },
    page: PageQuery,
  ): Observable<PageResponse<AuditEventResponse>> {
    return this.http.get<PageResponse<AuditEventResponse>>(apiUrl('/audit/events'), {
      params: pageParams(page, {
        eventType: filter.eventType,
        actorUserId: filter.actorUserId,
      }),
    });
  }
}
