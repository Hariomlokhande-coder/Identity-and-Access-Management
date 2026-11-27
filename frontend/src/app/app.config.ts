import { provideHttpClient, withInterceptors } from '@angular/common/http';
import { ApplicationConfig, provideBrowserGlobalErrorListeners } from '@angular/core';
import { provideRouter, withComponentInputBinding, withInMemoryScrolling } from '@angular/router';

import { routes } from './app.routes';
import { authInterceptor } from './core/http/auth.interceptor';
import { correlationInterceptor } from './core/http/correlation.interceptor';
import { errorInterceptor } from './core/http/error.interceptor';

export const appConfig: ApplicationConfig = {
  providers: [
    provideBrowserGlobalErrorListeners(),
    provideRouter(
      routes,
      // Route params and query params arrive as component inputs, which keeps the
      // screens free of ActivatedRoute plumbing.
      withComponentInputBinding(),
      withInMemoryScrolling({ scrollPositionRestoration: 'top' }),
    ),
    provideHttpClient(
      // Order matters. The first entry is the outermost, so the error interceptor
      // only sees a failure after the auth interceptor has had its one chance to
      // refresh and replay - otherwise every expired token would raise a toast on
      // its way to being silently recovered.
      withInterceptors([errorInterceptor, authInterceptor, correlationInterceptor]),
    ),
  ],
};
