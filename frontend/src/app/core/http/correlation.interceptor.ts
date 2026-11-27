import { HttpEvent, HttpHandlerFn, HttpRequest } from '@angular/common/http';
import { Observable } from 'rxjs';

/**
 * Stamps every request with a correlation id.
 *
 * X-Correlation-Id is one of the three headers the server's CORS policy allows,
 * and it is echoed back in every error body - which is what makes a user-reported
 * failure findable in the server logs.
 */
export function correlationInterceptor(
  request: HttpRequest<unknown>,
  next: HttpHandlerFn,
): Observable<HttpEvent<unknown>> {
  return next(request.clone({ setHeaders: { 'X-Correlation-Id': newCorrelationId() } }));
}

function newCorrelationId(): string {
  if (typeof crypto !== 'undefined' && 'randomUUID' in crypto) {
    return crypto.randomUUID();
  }
  return Math.random().toString(36).slice(2) + Date.now().toString(36);
}
