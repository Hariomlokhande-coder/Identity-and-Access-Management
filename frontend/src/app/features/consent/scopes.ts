export interface ScopeDescription {
  title: string;
  detail: string;
}

/**
 * Plain-language descriptions of the standard OIDC scopes.
 *
 * A consent screen that shows raw scope strings is asking the user to approve
 * something they cannot evaluate. An unrecognised scope is shown as-is rather than
 * glossed over - saying nothing is better than inventing a reassuring description
 * for a permission this screen does not understand.
 */
const KNOWN: Record<string, ScopeDescription> = {
  openid: {
    title: 'Confirm who you are',
    detail: 'Sign you in and share your user identifier.',
  },
  profile: {
    title: 'Read your basic profile',
    detail: 'Your name and account details, if set.',
  },
  email: {
    title: 'Read your email address',
    detail: 'The address on your account, and whether it is verified.',
  },
  offline_access: {
    title: 'Stay signed in',
    detail: 'Keep access after you close the application, until you withdraw it.',
  },
};

export function describeScope(scope: string): ScopeDescription {
  return (
    KNOWN[scope] ?? {
      title: scope,
      detail: 'A permission defined by this application.',
    }
  );
}
