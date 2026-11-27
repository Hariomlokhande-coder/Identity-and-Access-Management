import { HttpClient } from '@angular/common/http';
import { Injectable, inject } from '@angular/core';
import { Observable } from 'rxjs';
import { MessageResponse, PageQuery, PageResponse } from '../models/common';
import {
  AssignRolesRequest,
  CreateUserRequest,
  UpdateEmailRequest,
  UpdateStatusRequest,
  UserResponse,
  UserSearchQuery,
} from '../models/user';
import { apiUrl, pageParams } from './api';

@Injectable({ providedIn: 'root' })
export class UsersApi {
  private readonly http = inject(HttpClient);

  me(): Observable<UserResponse> {
    return this.http.get<UserResponse>(apiUrl('/users/me'));
  }

  updateOwnEmail(request: UpdateEmailRequest): Observable<UserResponse> {
    return this.http.put<UserResponse>(apiUrl('/users/me/email'), request);
  }

  search(filter: UserSearchQuery, page: PageQuery): Observable<PageResponse<UserResponse>> {
    return this.http.get<PageResponse<UserResponse>>(apiUrl('/users'), {
      params: pageParams(page, { query: filter.query, status: filter.status }),
    });
  }

  get(id: string): Observable<UserResponse> {
    return this.http.get<UserResponse>(apiUrl('/users/' + id));
  }

  create(request: CreateUserRequest): Observable<UserResponse> {
    return this.http.post<UserResponse>(apiUrl('/users'), request);
  }

  updateEmail(id: string, request: UpdateEmailRequest): Observable<UserResponse> {
    return this.http.put<UserResponse>(apiUrl('/users/' + id + '/email'), request);
  }

  updateStatus(id: string, request: UpdateStatusRequest): Observable<UserResponse> {
    return this.http.put<UserResponse>(apiUrl('/users/' + id + '/status'), request);
  }

  assignRoles(id: string, request: AssignRolesRequest): Observable<UserResponse> {
    return this.http.put<UserResponse>(apiUrl('/users/' + id + '/roles'), request);
  }

  /** Clears a lockout early instead of waiting for it to lapse. */
  unlock(id: string): Observable<MessageResponse> {
    return this.http.post<MessageResponse>(apiUrl('/users/' + id + '/unlock'), {});
  }

  delete(id: string): Observable<void> {
    return this.http.delete<void>(apiUrl('/users/' + id));
  }
}
