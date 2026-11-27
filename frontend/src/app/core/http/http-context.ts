import { HttpContextToken } from '@angular/common/http';

/**
 * Marks a request that must not carry a bearer token and must not trigger a
 * refresh-and-retry. Set on the endpoints that establish a session in the first
 * place - sending a stale token to them only produces confusing 401s.
 */
export const SKIP_AUTH = new HttpContextToken<boolean>(() => false);

/**
 * Suppresses the global error toast for one request, for screens that render the
 * failure inline instead (login being the obvious one).
 */
export const SKIP_ERROR_TOAST = new HttpContextToken<boolean>(() => false);
