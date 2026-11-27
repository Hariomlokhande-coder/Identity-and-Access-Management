import { Injectable, computed, signal } from '@angular/core';
import { AccessTokenClaims, Permission, TokenResponse } from '../models/auth';
import { decodeAccessToken, isExpired } from './jwt';

const REFRESH_KEY = 'iam.refresh_token';

/**
 * Holds the credentials of the current console session.
 *
 * The access token lives in memory only: it is short lived (10 minutes by default)
 * and never needs to survive a reload. The refresh token is persisted so that a
 * reload does not force a re-login, which puts it within reach of an XSS payload -
 * the accepted trade-off for a token-authenticated SPA with no backend-for-frontend.
 * The blast radius is bounded by rotation: the server revokes the whole family the
 * moment a rotated token is replayed.
 */
@Injectable({ providedIn: 'root' })
export class TokenStore {
  private readonly accessToken = signal<string | null>(null);
  private readonly refreshToken = signal<string | null>(readStoredRefreshToken());

  readonly claims = computed<AccessTokenClaims | null>(() => {
    const token = this.accessToken();
    return token ? decodeAccessToken(token) : null;
  });

  readonly permissions = computed<ReadonlySet<Permission>>(
    () => new Set(this.claims()?.perms ?? []),
  );

  readonly roles = computed<string[]>(() => this.claims()?.roles ?? []);
  readonly userId = computed<string | null>(() => this.claims()?.sub ?? null);
  readonly sessionId = computed<string | null>(() => this.claims()?.sid ?? null);

  /** A persisted refresh token counts: the access token is restored from it on boot. */
  readonly isAuthenticated = computed(() => this.accessToken() !== null || this.refreshToken() !== null);

  readonly accessTokenExpired = computed(() => isExpired(this.claims()));

  currentAccessToken(): string | null {
    return this.accessToken();
  }

  currentRefreshToken(): string | null {
    return this.refreshToken();
  }

  has(permission: Permission): boolean {
    return this.permissions().has(permission);
  }

  hasAny(...permissions: Permission[]): boolean {
    const granted = this.permissions();
    return permissions.some((permission) => granted.has(permission));
  }

  /**
   * Applies a token response. A refresh response that omits refresh_token leaves
   * the stored one alone rather than clearing it.
   */
  accept(tokens: TokenResponse): void {
    this.accessToken.set(tokens.access_token);
    if (tokens.refresh_token) {
      this.refreshToken.set(tokens.refresh_token);
      writeStoredRefreshToken(tokens.refresh_token);
    }
  }

  clear(): void {
    this.accessToken.set(null);
    this.refreshToken.set(null);
    writeStoredRefreshToken(null);
  }
}

function readStoredRefreshToken(): string | null {
  try {
    return localStorage.getItem(REFRESH_KEY);
  } catch {
    // Private mode or blocked storage. The session still works, it just will not
    // survive a reload.
    return null;
  }
}

function writeStoredRefreshToken(value: string | null): void {
  try {
    if (value === null) {
      localStorage.removeItem(REFRESH_KEY);
    } else {
      localStorage.setItem(REFRESH_KEY, value);
    }
  } catch {
    /* ignore - see readStoredRefreshToken */
  }
}
