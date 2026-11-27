import { HttpErrorResponse } from '@angular/common/http';
import { ApiError, OAuthError } from '../models/common';

/** The parsed body of a failed request, whichever of the two shapes it used. */
export interface ParsedError {
  status: number;
  code: string;
  message: string;
  correlationId?: string;
  /** Field-level messages from a 400 VALIDATION_FAILED. */
  fieldErrors?: Record<string, string>;
  /** Seconds to wait, from the Retry-After header on a 429 or 503. */
  retryAfterSeconds?: number;
}

export function parseError(error: unknown): ParsedError {
  if (!(error instanceof HttpErrorResponse)) {
    return { status: 0, code: 'UNKNOWN', message: 'Something went wrong.' };
  }

  // status 0 means the request never got a response: server down, DNS, or a CORS
  // rejection. Saying "network" is honest; guessing at a cause is not.
  if (error.status === 0) {
    return {
      status: 0,
      code: 'NETWORK',
      message: 'Could not reach the server. Check that the backend is running.',
    };
  }

  const retryAfter = error.headers?.get('Retry-After');
  const retryAfterSeconds = retryAfter ? Number(retryAfter) : undefined;
  const body = error.error as Partial<ApiError> & Partial<OAuthError>;

  if (body && typeof body === 'object' && 'code' in body && body.code) {
    return {
      status: error.status,
      code: body.code,
      message: body.message ?? fallbackMessage(error.status),
      correlationId: body.correlationId,
      fieldErrors: (body as ApiError).details,
      retryAfterSeconds: Number.isFinite(retryAfterSeconds) ? retryAfterSeconds : undefined,
    };
  }

  // OAuth2 endpoints answer with the spec shape instead.
  if (body && typeof body === 'object' && 'error' in body && body.error) {
    return {
      status: error.status,
      code: body.error,
      message: body.error_description ?? body.error,
      retryAfterSeconds: Number.isFinite(retryAfterSeconds) ? retryAfterSeconds : undefined,
    };
  }

  return {
    status: error.status,
    code: String(error.status),
    message: fallbackMessage(error.status),
    retryAfterSeconds: Number.isFinite(retryAfterSeconds) ? retryAfterSeconds : undefined,
  };
}

function fallbackMessage(status: number): string {
  switch (status) {
    case 401:
      return 'Your session has ended. Sign in again.';
    case 403:
      return 'You are not allowed to do that.';
    case 404:
      return 'Not found.';
    case 429:
      return 'Too many requests. Wait a moment and try again.';
    case 503:
      return 'A dependency is unavailable. Try again shortly.';
    default:
      return 'Something went wrong.';
  }
}

/** Turns a parsed error into the sentence shown to the user. */
export function errorText(error: ParsedError): string {
  if (error.retryAfterSeconds) {
    return `${error.message} Try again in ${error.retryAfterSeconds}s.`;
  }
  const fields = error.fieldErrors ? Object.values(error.fieldErrors) : [];
  return fields.length ? `${error.message} ${fields.join(' ')}` : error.message;
}
