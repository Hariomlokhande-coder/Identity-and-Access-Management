/** Mirrors com.example.iam.common.PageResponse. */
export interface PageResponse<T> {
  items: T[];
  page: number;
  size: number;
  totalElements: number;
  totalPages: number;
}

/**
 * The single error shape every non-OAuth2 endpoint returns.
 * Mirrors the body documented in README "Errors".
 */
export interface ApiError {
  timestamp: string;
  status: number;
  code: ErrorCode;
  message: string;
  path: string;
  correlationId: string;
  details?: Record<string, string>;
}

/** OAuth2 endpoints return the spec shape instead, because client libraries parse it. */
export interface OAuthError {
  error: string;
  error_description?: string;
}

export type ErrorCode =
  | 'VALIDATION_FAILED'
  | 'INVALID_REQUEST'
  | 'PASSWORD_POLICY_VIOLATION'
  | 'UNAUTHENTICATED'
  | 'INVALID_CREDENTIALS'
  | 'INVALID_TOKEN'
  | 'TOKEN_EXPIRED'
  | 'INVALID_REFRESH_TOKEN'
  | 'FORBIDDEN'
  | 'ACCOUNT_LOCKED'
  | 'ACCOUNT_DISABLED'
  | 'EMAIL_NOT_VERIFIED'
  | 'CONSENT_REQUIRED'
  | 'NOT_FOUND'
  | 'METHOD_NOT_ALLOWED'
  | 'CONFLICT'
  | 'UNSUPPORTED_MEDIA_TYPE'
  | 'RATE_LIMITED'
  | 'INTERNAL_ERROR'
  | 'SERVICE_UNAVAILABLE';

export interface MessageResponse {
  message: string;
}

/** Query parameters accepted by every Pageable endpoint. */
export interface PageQuery {
  page?: number;
  size?: number;
  sort?: string;
}
