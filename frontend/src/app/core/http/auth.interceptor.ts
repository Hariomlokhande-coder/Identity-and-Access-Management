import { HttpErrorResponse, HttpEvent, HttpHandlerFn, HttpRequest } from '@angular/common/http';
import { inject } from '@angular/core';
import { Observable, catchError, switchMap, throwError } from 'rxjs';
import { AuthService } from '../auth/auth.service';
import { TokenStore } from '../auth/token-store';
import { SKIP_AUTH } from './http-context';

/**
 * Attaches the bearer token, and on a 401 refreshes once and replays the request.
 *
 * Only one retry is attempted. If the replayed request is rejected too, the
 * session is genuinely gone and retrying again would just burn refresh tokens.
 */
export function authInterceptor(
  request: HttpRequest<unknown>,
  next: HttpHandlerFn,
): Observable<HttpEvent<unknown>> {
  if (request.context.get(SKIP_AUTH)) {
    return next(request);
  }

  const store = inject(TokenStore);
  const auth = inject(AuthService);

  return next(withBearer(request, store.currentAccessToken())).pipe(
    catchError((error: unknown) => {
      if (!isUnauthorized(error) || !store.currentRefreshToken()) {
        return throwError(() => error);
      }
      return auth.refresh().pipe(
        switchMap((tokens) => next(withBearer(request, tokens.access_token))),
        catchError(() => {
          auth.forceSignOut(location.pathname + location.search);
          return throwError(() => error);
        }),
      );
    }),
  );
}

function withBearer(request: HttpRequest<unknown>, token: string | null): HttpRequest<unknown> {
  if (!token) {
    return request;
  }
  return request.clone({ setHeaders: { Authorization: `Bearer ${token}` } });
}

function isUnauthorized(error: unknown): boolean {
  return error instanceof HttpErrorResponse && error.status === 401;
}
