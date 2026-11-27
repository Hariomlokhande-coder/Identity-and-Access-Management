/** POST /auth/login, /auth/refresh and /oauth2/token all return this. */
export interface TokenResponse {
  access_token: string;
  token_type: string;
  expires_in: number;
  refresh_token?: string;
  id_token?: string;
  scope?: string;
  session_id?: string;
}

export interface LoginRequest {
  email: string;
  password: string;
}

export interface RegisterRequest {
  email: string;
  password: string;
}

export interface EmailOnlyRequest {
  email: string;
}

export interface VerifyEmailRequest {
  token: string;
}

export interface ResetPasswordRequest {
  token: string;
  newPassword: string;
}

export interface ChangePasswordRequest {
  currentPassword: string;
  newPassword: string;
}

export interface LogoutRequest {
  refreshToken?: string;
  allDevices: boolean;
}

/**
 * Claims the platform puts in its own access tokens. Short names match JwtService:
 * sid = session id, pv = permission version, perms = permission names.
 *
 * These are read only to decide what the UI offers. Every one of them is enforced
 * again on the server, so a tampered token buys nothing but a broken screen.
 */
export interface AccessTokenClaims {
  sub: string;
  iss: string;
  aud: string | string[];
  exp: number;
  iat: number;
  sid: string;
  pv: number;
  roles: string[];
  perms: Permission[];
  scope?: string;
  token_use: 'access' | 'id';
}

/** Seeded by V2__seed_rbac.sql. */
export type Permission =
  | 'PROFILE_READ'
  | 'PROFILE_UPDATE'
  | 'USER_READ'
  | 'USER_CREATE'
  | 'USER_UPDATE'
  | 'USER_DELETE'
  | 'ROLE_READ'
  | 'ROLE_MANAGE'
  | 'CLIENT_READ'
  | 'CLIENT_MANAGE'
  | 'SESSION_ADMIN'
  | 'AUDIT_READ';
