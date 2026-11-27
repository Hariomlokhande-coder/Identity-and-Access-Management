import { HttpClient } from '@angular/common/http';
import { Injectable, inject } from '@angular/core';
import { Observable } from 'rxjs';
import {
  CreateRoleRequest,
  PermissionResponse,
  RoleResponse,
  UpdateRoleRequest,
} from '../models/role';
import { apiUrl } from './api';

@Injectable({ providedIn: 'root' })
export class RolesApi {
  private readonly http = inject(HttpClient);

  list(): Observable<RoleResponse[]> {
    return this.http.get<RoleResponse[]>(apiUrl('/roles'));
  }

  get(id: string): Observable<RoleResponse> {
    return this.http.get<RoleResponse>(apiUrl('/roles/' + id));
  }

  /** Every permission the platform knows about - the palette for the role editor. */
  permissions(): Observable<PermissionResponse[]> {
    return this.http.get<PermissionResponse[]>(apiUrl('/roles/permissions'));
  }

  create(request: CreateRoleRequest): Observable<RoleResponse> {
    return this.http.post<RoleResponse>(apiUrl('/roles'), request);
  }

  updatePermissions(id: string, request: UpdateRoleRequest): Observable<RoleResponse> {
    return this.http.put<RoleResponse>(apiUrl('/roles/' + id + '/permissions'), request);
  }

  delete(id: string): Observable<void> {
    return this.http.delete<void>(apiUrl('/roles/' + id));
  }
}
