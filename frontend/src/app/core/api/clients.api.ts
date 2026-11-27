import { HttpClient } from '@angular/common/http';
import { Injectable, inject } from '@angular/core';
import { Observable } from 'rxjs';
import {
  ClientCredentialsResponse,
  ClientResponse,
  CreateClientRequest,
  UpdateClientRequest,
} from '../models/client';
import { apiUrl } from './api';

@Injectable({ providedIn: 'root' })
export class ClientsApi {
  private readonly http = inject(HttpClient);

  list(): Observable<ClientResponse[]> {
    return this.http.get<ClientResponse[]>(apiUrl('/clients'));
  }

  get(id: string): Observable<ClientResponse> {
    return this.http.get<ClientResponse>(apiUrl('/clients/' + id));
  }

  /** The response carries the plaintext secret exactly once. */
  create(request: CreateClientRequest): Observable<ClientCredentialsResponse> {
    return this.http.post<ClientCredentialsResponse>(apiUrl('/clients'), request);
  }

  update(id: string, request: UpdateClientRequest): Observable<ClientResponse> {
    return this.http.put<ClientResponse>(apiUrl('/clients/' + id), request);
  }

  /** Issues a new secret and invalidates the old one immediately. */
  rotateSecret(id: string): Observable<ClientCredentialsResponse> {
    return this.http.post<ClientCredentialsResponse>(apiUrl('/clients/' + id + '/rotate-secret'), {});
  }

  delete(id: string): Observable<void> {
    return this.http.delete<void>(apiUrl('/clients/' + id));
  }
}
