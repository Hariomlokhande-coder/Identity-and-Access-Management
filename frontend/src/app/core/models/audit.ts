export type AuditOutcome = 'SUCCESS' | 'FAILURE';

/** Mirrors com.example.iam.audit.AuditEventType. */
export type AuditEventType =
  | 'USER_REGISTERED'
  | 'EMAIL_VERIFIED'
  | 'EMAIL_VERIFICATION_RESENT'
  | 'LOGIN'
  | 'LOGOUT'
  | 'ACCOUNT_LOCKED'
  | 'ACCOUNT_UNLOCKED'
  | 'ACCOUNT_STATUS_CHANGED'
  | 'ACCOUNT_DELETED'
  | 'PASSWORD_CHANGED'
  | 'PASSWORD_RESET_REQUESTED'
  | 'PASSWORD_RESET_COMPLETED'
  | 'TOKEN_REFRESHED'
  | 'REFRESH_TOKEN_REUSE_DETECTED'
  | 'SESSION_REVOKED'
  | 'ROLE_CREATED'
  | 'ROLE_UPDATED'
  | 'ROLE_DELETED'
  | 'ROLE_ASSIGNMENT_CHANGED'
  | 'CLIENT_CREATED'
  | 'CLIENT_UPDATED'
  | 'CLIENT_DELETED'
  | 'CLIENT_SECRET_ROTATED'
  | 'OAUTH_AUTHORIZATION_GRANTED'
  | 'OAUTH_CONSENT_WITHDRAWN';

/** The same list as the union above, for populating the filter dropdown. */
export const AUDIT_EVENT_TYPES: AuditEventType[] = [
  'USER_REGISTERED',
  'EMAIL_VERIFIED',
  'EMAIL_VERIFICATION_RESENT',
  'LOGIN',
  'LOGOUT',
  'ACCOUNT_LOCKED',
  'ACCOUNT_UNLOCKED',
  'ACCOUNT_STATUS_CHANGED',
  'ACCOUNT_DELETED',
  'PASSWORD_CHANGED',
  'PASSWORD_RESET_REQUESTED',
  'PASSWORD_RESET_COMPLETED',
  'TOKEN_REFRESHED',
  'REFRESH_TOKEN_REUSE_DETECTED',
  'SESSION_REVOKED',
  'ROLE_CREATED',
  'ROLE_UPDATED',
  'ROLE_DELETED',
  'ROLE_ASSIGNMENT_CHANGED',
  'CLIENT_CREATED',
  'CLIENT_UPDATED',
  'CLIENT_DELETED',
  'CLIENT_SECRET_ROTATED',
  'OAUTH_AUTHORIZATION_GRANTED',
  'OAUTH_CONSENT_WITHDRAWN',
];

export interface AuditEventResponse {
  id: string;
  eventType: AuditEventType;
  outcome: AuditOutcome;
  actorUserId: string | null;
  targetId: string | null;
  clientId: string | null;
  ipAddress: string | null;
  correlationId: string | null;
  detail: string | null;
  createdAt: string;
}

/**
 * The events worth calling out in red. A reuse detection in particular means the
 * server revoked a whole token family because a rotated refresh token came back -
 * either a stolen token or a broken client.
 */
export const CRITICAL_EVENTS: ReadonlySet<AuditEventType> = new Set<AuditEventType>([
  'REFRESH_TOKEN_REUSE_DETECTED',
  'ACCOUNT_LOCKED',
  'ACCOUNT_DELETED',
  'CLIENT_SECRET_ROTATED',
  'CLIENT_DELETED',
  'ROLE_DELETED',
]);
