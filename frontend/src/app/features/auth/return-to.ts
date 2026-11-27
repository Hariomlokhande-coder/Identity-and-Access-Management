import { environment } from '../../../environments/environment';

/**
 * Decides whether a return_to parameter may be navigated to.
 *
 * The login screen is handed this URL by the authorize endpoint so the OAuth flow
 * can be replayed once a session exists. It arrives in the query string, which
 * means anyone can put anything there - an unchecked redirect here would turn the
 * identity provider's own login page into an open redirect, the classic way to make
 * a phishing link look legitimate.
 *
 * Only two destinations are ever legitimate: somewhere in this application, or the
 * backend that issued the redirect in the first place. Anything else is discarded
 * rather than sanitised.
 */
export function safeReturnTo(raw: string | null | undefined): string | null {
  if (!raw) {
    return null;
  }

  let target: URL;
  try {
    target = new URL(raw, location.origin);
  } catch {
    return null;
  }

  if (target.protocol !== 'https:' && target.protocol !== 'http:') {
    return null;
  }

  const allowed = new Set<string>([location.origin]);
  if (environment.apiBase) {
    try {
      allowed.add(new URL(environment.apiBase).origin);
    } catch {
      /* a malformed apiBase simply contributes no origin */
    }
  }

  return allowed.has(target.origin) ? target.toString() : null;
}

/** True when the destination leaves this SPA and needs a full page navigation. */
export function isExternal(url: string): boolean {
  try {
    return new URL(url, location.origin).origin !== location.origin;
  } catch {
    return false;
  }
}
