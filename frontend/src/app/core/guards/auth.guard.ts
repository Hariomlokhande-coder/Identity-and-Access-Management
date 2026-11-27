import { inject } from '@angular/core';
import { CanActivateFn, Router } from '@angular/router';
import { map } from 'rxjs';
import { AuthService } from '../auth/auth.service';
import { Permission } from '../models/auth';

/**
 * Blocks a route until a usable access token exists. On a cold load that means
 * waiting for the refresh call, otherwise permissions would be read from an empty
 * token and every admin link would vanish for a split second.
 */
export const authGuard: CanActivateFn = (_route, state) => {
  const auth = inject(AuthService);
  const router = inject(Router);

  return auth
    .ensureSession()
    .pipe(
      map((valid) =>
        valid ? true : router.createUrlTree(['/login'], { queryParams: { return_to: state.url } }),
      ),
    );
};

/** Keeps a signed-in user off the login and registration screens. */
export const guestGuard: CanActivateFn = () => {
  const auth = inject(AuthService);
  const router = inject(Router);

  return auth.ensureSession().pipe(map((valid) => (valid ? router.createUrlTree(['/']) : true)));
};

/**
 * Requires at least one of the given permissions.
 *
 * This hides screens the server would refuse anyway - it is a courtesy, not a
 * control. Every one of these permissions is checked again by @PreAuthorize.
 */
export function permissionGuard(...permissions: Permission[]): CanActivateFn {
  return (_route, state) => {
    const auth = inject(AuthService);
    const router = inject(Router);

    return auth.ensureSession().pipe(
      map((valid) => {
        if (!valid) {
          return router.createUrlTree(['/login'], { queryParams: { return_to: state.url } });
        }
        return auth.hasAny(...permissions) ? true : router.createUrlTree(['/forbidden']);
      }),
    );
  };
}
