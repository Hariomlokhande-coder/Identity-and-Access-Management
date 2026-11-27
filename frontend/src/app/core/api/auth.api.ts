import { HttpClient, HttpContext } from '@angular/common/http';
import { Injectable, inject } from '@angular/core';
import { Observable } from 'rxjs';
import {
  ChangePasswordRequest,
  EmailOnlyRequest,
  LoginRequest,
  LogoutRequest,
  RegisterRequest,
  ResetPasswordRequest,
  TokenResponse,
  VerifyEmailRequest,
} from '../models/auth';
import { MessageResponse } from '../models/common';
import { SKIP_AUTH, SKIP_ERROR_TOAST } from '../http/http-context';
import { apiUrl } from './api';

@Injectable({ providedIn: 'root' })
export class AuthApi {
  private readonly http = inject(HttpClient);

  /**
   * withCredentials is required on login: the response also sets the SSO cookie
   * that /oauth2/authorize later reads to recognise the browser.
   */
  login(request: LoginRequest): Observable<TokenResponse> {
    return this.http.post<TokenResponse>(apiUrl('/auth/login'), request, {
      withCredentials: true,
      context: anonymous(),
    });
  }

  /**
   * Never send the expiring access token here. If the interceptor tried to refresh
   * this call the two would deadlock on the same single-flight promise.
   */
  refresh(refreshToken: string): Observable<TokenResponse> {
    return this.http.post<TokenResponse>(
      apiUrl('/auth/refresh'),
      { refreshToken },
      { withCredentials: true, context: anonymous() },
    );
  }

  logout(request: LogoutRequest): Observable<MessageResponse> {
    return this.http.post<MessageResponse>(apiUrl('/auth/logout'), request, {
      withCredentials: true,
    });
  }

  /** Always the same generic response, whether or not the address was already taken. */
  register(request: RegisterRequest): Observable<MessageResponse> {
    return this.http.post<MessageResponse>(apiUrl('/auth/register'), request, {
      context: anonymous(),
    });
  }

  verifyEmail(request: VerifyEmailRequest): Observable<MessageResponse> {
    return this.http.post<MessageResponse>(apiUrl('/auth/verify-email'), request, {
      context: anonymous(),
    });
  }

  resendVerification(request: EmailOnlyRequest): Observable<MessageResponse> {
    return this.http.post<MessageResponse>(apiUrl('/auth/resend-verification'), request, {
      context: anonymous(),
    });
  }

  forgotPassword(request: EmailOnlyRequest): Observable<MessageResponse> {
    return this.http.post<MessageResponse>(apiUrl('/auth/forgot-password'), request, {
      context: anonymous(),
    });
  }

  resetPassword(request: ResetPasswordRequest): Observable<MessageResponse> {
    return this.http.post<MessageResponse>(apiUrl('/auth/reset-password'), request, {
      context: anonymous(),
    });
  }

  changePassword(request: ChangePasswordRequest): Observable<MessageResponse> {
    return this.http.post<MessageResponse>(apiUrl('/auth/change-password'), request);
  }
}

/**
 * The context every credential-establishing call uses: no bearer token, and no
 * global toast. These screens render their failure inline, next to the field that
 * caused it, and a floating duplicate on top of that is just noise.
 */
function anonymous(): HttpContext {
  return new HttpContext().set(SKIP_AUTH, true).set(SKIP_ERROR_TOAST, true);
}
