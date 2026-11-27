import { HttpEvent, HttpHandlerFn, HttpRequest } from '@angular/common/http';
import { inject } from '@angular/core';
import { Observable, catchError, throwError } from 'rxjs';
import { NotificationsService } from '../notifications.service';
import { errorText, parseError } from './api-error';
import { SKIP_ERROR_TOAST } from './http-context';

/**
 * Surfaces failures the user would otherwise never see, then rethrows so the
 * calling component can still react. A 401 is left silent: the auth interceptor
 * either recovers from it or redirects to the login screen, and a toast on top of
 * that is noise.
 */
export function errorInterceptor(
  request: HttpRequest<unknown>,
  next: HttpHandlerFn,
): Observable<HttpEvent<unknown>> {
  const notifications = inject(NotificationsService);

  return next(request).pipe(
    catchError((error: unknown) => {
      if (!request.context.get(SKIP_ERROR_TOAST)) {
        const parsed = parseError(error);
        if (parsed.status !== 401) {
          notifications.error(errorText(parsed), parsed.correlationId);
        }
      }
      return throwError(() => error);
    }),
  );
}
