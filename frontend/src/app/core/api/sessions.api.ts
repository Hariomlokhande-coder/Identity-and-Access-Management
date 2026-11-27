import { HttpClient } from '@angular/common/http';
import { Injectable, inject } from '@angular/core';
import { Observable } from 'rxjs';
import { MessageResponse } from '../models/common';
import { SessionResponse } from '../models/session';
import { apiUrl } from './api';

@Injectable({ providedIn: 'root' })
export class SessionsApi {
  private readonly http = inject(HttpClient);

  /** The caller's own sessions, one per signed-in device. */
  mine(): Observable<SessionResponse[]> {
    return this.http.get<SessionResponse[]>(apiUrl('/sessions'));
  }

  revoke(id: string): Observable<MessageResponse> {
    return this.http.delete<MessageResponse>(apiUrl('/sessions/' + id));
  }

  /** Keeps the caller's own session, so this page stays signed in. */
  revokeAll(): Observable<MessageResponse> {
    return this.http.delete<MessageResponse>(apiUrl('/sessions/all'));
  }

  /** Requires SESSION_ADMIN: signs another user out of everything, current included. */
  revokeForUser(userId: string): Observable<MessageResponse> {
    return this.http.delete<MessageResponse>(apiUrl('/sessions/users/' + userId));
  }
}
