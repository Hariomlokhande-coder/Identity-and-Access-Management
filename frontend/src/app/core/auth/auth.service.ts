import { Injectable, computed, inject, signal } from '@angular/core';
import { Router } from '@angular/router';
import { Observable, catchError, map, of, shareReplay, tap, throwError } from 'rxjs';
import { AuthApi } from '../api/auth.api';
import { LoginRequest, Permission, TokenResponse } from '../models/auth';
import { TokenStore } from './token-store';

/**
 * Owns the console's own session: signing in, keeping the access token fresh, and
 * signing out.
 *
 * The one rule that shapes this class: there must never be two refresh calls in
 * flight. The server rotates refresh tokens and treats a replayed one as theft,
 * revoking the entire family - so a race between two tabs' worth of expired
 * requests would not just fail, it would log the user out everywhere. Every caller
 * therefore shares a single in-flight refresh.
 */
@Injectable({ providedIn: 'root' })
export class AuthService {
  private readonly api = inject(AuthApi);
  private readonly store = inject(TokenStore);
  private readonly router = inject(Router);

  /** The shared in-flight refresh, or null when none is running. */
  private inFlightRefresh: Observable<TokenResponse> | null = null;

  private readonly bootstrapped = signal(false);

  readonly isAuthenticated = this.store.isAuthenticated;
  readonly claims = this.store.claims;
  readonly permissions = this.store.permissions;
  readonly roles = this.store.roles;
  readonly userId = this.store.userId;
  readonly ready = this.bootstrapped.asReadonly();

  readonly isAdmin = computed(() =>
    this.store.hasAny('USER_READ', 'ROLE_READ', 'CLIENT_READ', 'AUDIT_READ'),
  );

  has(permission: Permission): boolean {
    return this.store.has(permission);
  }

  hasAny(...permissions: Permission[]): boolean {
    return this.store.hasAny(...permissions);
  }

  login(request: LoginRequest): Observable<TokenResponse> {
    return this.api.login(request).pipe(
      tap((tokens) => {
        this.store.accept(tokens);
        this.bootstrapped.set(true);
      }),
    );
  }

  /**
   * Called by the guards before a protected route renders. On a cold load only the
   * refresh token survives, so the access token has to be minted before anything
   * that reads permissions can decide what to show.
   */
  ensureSession(): Observable<boolean> {
    if (this.store.currentAccessToken() && !this.store.accessTokenExpired()) {
      return of(true);
    }
    if (!this.store.currentRefreshToken()) {
      this.bootstrapped.set(true);
      return of(false);
    }
    return this.refresh().pipe(
      map(() => true),
      catchError(() => of(false)),
    );
  }

  /**
   * Refreshes the access token, joining any refresh already running rather than
   * starting a second one.
   */
  refresh(): Observable<TokenResponse> {
    if (this.inFlightRefresh) {
      return this.inFlightRefresh;
    }
    const refreshToken = this.store.currentRefreshToken();
    if (!refreshToken) {
      return throwError(() => new Error('No refresh token'));
    }

    this.inFlightRefresh = this.api.refresh(refreshToken).pipe(
      tap({
        next: (tokens) => {
          this.store.accept(tokens);
          this.bootstrapped.set(true);
          this.inFlightRefresh = null;
        },
        error: () => {
          // The family is gone: either it expired or the server detected a replay.
          // Either way this browser no longer holds a usable session.
          this.inFlightRefresh = null;
          this.store.clear();
          this.bootstrapped.set(true);
        },
      }),
      shareReplay({ bufferSize: 1, refCount: false }),
    );
    return this.inFlightRefresh;
  }

  /**
   * Ends the session. The local state is cleared whether or not the server call
   * succeeds - a failed logout must not leave a signed-in-looking UI behind.
   */
  logout(allDevices = false): Observable<void> {
    const refreshToken = this.store.currentRefreshToken() ?? undefined;
    return this.api.logout({ refreshToken, allDevices }).pipe(
      catchError(() => of(null)),
      tap(() => this.store.clear()),
      map(() => undefined),
    );
  }

  /** Drops the session locally and sends the browser to the login screen. */
  forceSignOut(returnTo?: string): void {
    this.store.clear();
    void this.router.navigate(['/login'], {
      queryParams: returnTo ? { return_to: returnTo } : undefined,
    });
  }
}
