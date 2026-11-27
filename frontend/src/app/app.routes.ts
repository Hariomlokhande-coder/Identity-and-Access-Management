import { Routes } from '@angular/router';
import { authGuard, guestGuard, permissionGuard } from './core/guards/auth.guard';

export const routes: Routes = [
  // ---- Identity provider screens ----
  // These are the screens iam.login-url and iam.consent-url point at. They are not
  // part of the console frame: a user redirected here mid-OAuth flow should see a
  // sign-in page, not a navigation sidebar.
  {
    path: 'login',
    canActivate: [guestGuard],
    title: 'Sign in',
    loadComponent: () => import('./features/auth/login.component').then((m) => m.LoginComponent),
  },
  {
    path: 'register',
    canActivate: [guestGuard],
    title: 'Create an account',
    loadComponent: () =>
      import('./features/auth/register.component').then((m) => m.RegisterComponent),
  },
  {
    path: 'verify-email',
    title: 'Verify your email',
    loadComponent: () =>
      import('./features/auth/verify-email.component').then((m) => m.VerifyEmailComponent),
  },
  {
    path: 'forgot-password',
    title: 'Reset your password',
    loadComponent: () =>
      import('./features/auth/forgot-password.component').then((m) => m.ForgotPasswordComponent),
  },
  {
    path: 'reset-password',
    title: 'Choose a new password',
    loadComponent: () =>
      import('./features/auth/reset-password.component').then((m) => m.ResetPasswordComponent),
  },
  {
    // Authenticated by the SSO cookie rather than the console's bearer token, so no
    // guard here. If the cookie is missing the screen sends the user to sign in and
    // comes back.
    path: 'consent',
    title: 'Authorize application',
    loadComponent: () =>
      import('./features/consent/consent.component').then((m) => m.ConsentComponent),
  },

  // ---- The console itself ----
  {
    path: '',
    canActivate: [authGuard],
    loadComponent: () => import('./shell/shell.component').then((m) => m.ShellComponent),
    children: [
      { path: '', pathMatch: 'full', redirectTo: 'account/profile' },

      {
        path: 'account/profile',
        title: 'Profile',
        loadComponent: () =>
          import('./features/account/profile.component').then((m) => m.ProfileComponent),
      },
      {
        path: 'account/security',
        title: 'Security',
        loadComponent: () =>
          import('./features/account/security.component').then((m) => m.SecurityComponent),
      },
      {
        path: 'account/sessions',
        title: 'Devices',
        loadComponent: () =>
          import('./features/account/sessions.component').then((m) => m.SessionsComponent),
      },
      {
        path: 'account/apps',
        title: 'Connected apps',
        loadComponent: () =>
          import('./features/account/connected-apps.component').then(
            (m) => m.ConnectedAppsComponent,
          ),
      },

      {
        path: 'admin/users',
        canActivate: [permissionGuard('USER_READ')],
        title: 'Users',
        loadComponent: () =>
          import('./features/admin/users/user-list.component').then((m) => m.UserListComponent),
      },
      {
        path: 'admin/users/:id',
        canActivate: [permissionGuard('USER_READ')],
        title: 'User',
        loadComponent: () =>
          import('./features/admin/users/user-detail.component').then((m) => m.UserDetailComponent),
      },
      {
        path: 'admin/roles',
        canActivate: [permissionGuard('ROLE_READ')],
        title: 'Roles',
        loadComponent: () =>
          import('./features/admin/roles/role-list.component').then((m) => m.RoleListComponent),
      },
      {
        path: 'admin/clients',
        canActivate: [permissionGuard('CLIENT_READ')],
        title: 'Applications',
        loadComponent: () =>
          import('./features/admin/clients/client-list.component').then(
            (m) => m.ClientListComponent,
          ),
      },
      {
        path: 'admin/audit',
        canActivate: [permissionGuard('AUDIT_READ')],
        title: 'Audit log',
        loadComponent: () =>
          import('./features/admin/audit/audit-log.component').then((m) => m.AuditLogComponent),
      },

      {
        path: 'forbidden',
        title: 'Not allowed',
        loadComponent: () =>
          import('./features/forbidden.component').then((m) => m.ForbiddenComponent),
      },
    ],
  },

  { path: '**', redirectTo: '' },
];
