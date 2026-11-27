import { Pipe, PipeTransform } from '@angular/core';
import { BadgeTone } from './ui/badge.component';
import { ClientStatus } from '../core/models/client';
import { UserStatus } from '../core/models/user';
import { AuditEventType, AuditOutcome, CRITICAL_EVENTS } from '../core/models/audit';

/**
 * Absolute timestamps, in the viewer's locale.
 *
 * Audit and session screens deliberately avoid "3 hours ago": when someone is
 * working out what happened during an incident, a wall-clock time is what they
 * need to line up against other logs.
 */
@Pipe({ name: 'instant' })
export class InstantPipe implements PipeTransform {
  transform(value: string | null | undefined, style: 'full' | 'date' = 'full'): string {
    if (!value) {
      return '—';
    }
    const date = new Date(value);
    if (Number.isNaN(date.getTime())) {
      return '—';
    }
    // Both styles use the same medium month so a date-only column and a full
    // timestamp column side by side do not read as two different formats.
    return style === 'date'
      ? date.toLocaleDateString(undefined, { dateStyle: 'medium' })
      : date.toLocaleString(undefined, { dateStyle: 'medium', timeStyle: 'short' });
  }
}

/** Falls back to an em dash so an empty cell still occupies its column. */
@Pipe({ name: 'orDash' })
export class OrDashPipe implements PipeTransform {
  transform(value: string | number | null | undefined): string {
    return value === null || value === undefined || value === '' ? '—' : String(value);
  }
}

export function userStatusTone(status: UserStatus): BadgeTone {
  switch (status) {
    case 'ACTIVE':
      return 'ok';
    case 'PENDING_VERIFICATION':
      return 'warn';
    case 'DISABLED':
    case 'DELETED':
      return 'danger';
  }
}

export function clientStatusTone(status: ClientStatus): BadgeTone {
  return status === 'ACTIVE' ? 'ok' : 'danger';
}

/**
 * Three levels, so the log has a signal rather than a wall of red.
 *
 * Red is only for events that mean something is wrong - a replayed refresh token,
 * an account locked out by repeated failures. A deliberate deletion or a secret
 * rotation is consequential but intended, and a failed login is routine; both are
 * amber. Everything else is green.
 */
export function auditTone(eventType: AuditEventType, outcome: AuditOutcome): BadgeTone {
  if (ALARMING_EVENTS.has(eventType)) {
    return 'danger';
  }
  if (outcome !== 'SUCCESS' || CRITICAL_EVENTS.has(eventType)) {
    return 'warn';
  }
  return 'ok';
}

/** Events that mean something has gone wrong, rather than something notable happened. */
const ALARMING_EVENTS: ReadonlySet<AuditEventType> = new Set<AuditEventType>([
  'REFRESH_TOKEN_REUSE_DETECTED',
  'ACCOUNT_LOCKED',
]);

/**
 * Shortens an identifier for display, keeping the full value for the title
 * attribute. A table of untruncated UUIDs wraps every cell and triples the height
 * of the row it is in.
 */
@Pipe({ name: 'shortId' })
export class ShortIdPipe implements PipeTransform {
  transform(value: string | null | undefined, length = 8): string {
    if (!value) {
      return '—';
    }
    return value.length > length + 1 ? value.slice(0, length) + '…' : value;
  }
}

/** True while a lockout is still in force. */
export function isLockedNow(lockedUntil: string | null): boolean {
  return lockedUntil !== null && new Date(lockedUntil).getTime() > Date.now();
}
