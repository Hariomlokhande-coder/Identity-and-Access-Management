import { HttpClient, HttpHeaders } from '@angular/common/http';
import { Injectable, inject } from '@angular/core';
import { Observable } from 'rxjs';
import { MessageResponse } from '../models/common';
import { ConsentDecisionRequest, GrantedConsent, PendingAuthorization } from '../models/oauth';
import { apiUrl } from './api';

/** What the server answers when a consent decision is made over XHR. */
export interface ConsentDecisionResponse {
  /** Absolute URL back to the client, carrying either the code or an error. */
  redirectUri: string;
}

@Injectable({ providedIn: 'root' })
export class OAuthApi {
  private readonly http = inject(HttpClient);

  /**
   * Describes the authorization request the consent screen is being asked about.
   *
   * Authenticated by the SSO cookie rather than a bearer token, so the request has
   * to carry credentials. The browser arrived here from a top-level redirect, which
   * SameSite=Lax permits.
   */
  pending(requestId: string): Observable<PendingAuthorization> {
    return this.http.get<PendingAuthorization>(apiUrl('/oauth2/consent'), {
      params: { request_id: requestId },
      withCredentials: true,
    });
  }

  /**
   * Approves or denies a pending request.
   *
   * The browser endpoint answers a plain form post with a 302 straight back to the
   * client. That is unusable from a script: XHR follows the redirect itself and the
   * cross-origin hop to the client's redirect_uri fails CORS, burning the
   * authorization code on the way. Asking for JSON gets the destination back as
   * data instead, and this screen performs the navigation itself.
   */
  decide(request: ConsentDecisionRequest): Observable<ConsentDecisionResponse> {
    return this.http.post<ConsentDecisionResponse>(apiUrl('/oauth2/consent'), request, {
      withCredentials: true,
      headers: new HttpHeaders({ Accept: 'application/json' }),
    });
  }

  /** Applications this user has already granted access to. */
  granted(): Observable<GrantedConsent[]> {
    return this.http.get<GrantedConsent[]>(apiUrl('/oauth2/consents'));
  }

  /**
   * Withdraws consent. The server also signs the application out, so any tokens it
   * still holds stop working rather than outliving the decision.
   */
  withdraw(clientApplicationId: string): Observable<MessageResponse> {
    return this.http.delete<MessageResponse>(apiUrl('/oauth2/consents/' + clientApplicationId));
  }
}
