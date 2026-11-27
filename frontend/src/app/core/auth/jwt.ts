import { AccessTokenClaims } from '../models/auth';

/**
 * Decodes a JWT payload without verifying it.
 *
 * Verification is deliberately not attempted here. The browser has no business
 * deciding whether a token is authentic - every request is validated server side
 * against JWKS. These claims only drive what the UI bothers to render.
 */
export function decodeAccessToken(token: string): AccessTokenClaims | null {
  const parts = token.split('.');
  if (parts.length !== 3) {
    return null;
  }
  try {
    const payload = parts[1].replace(/-/g, '+').replace(/_/g, '/');
    const padded = payload.padEnd(payload.length + ((4 - (payload.length % 4)) % 4), '=');
    const json = decodeURIComponent(
      atob(padded)
        .split('')
        .map((c) => '%' + c.charCodeAt(0).toString(16).padStart(2, '0'))
        .join(''),
    );
    return JSON.parse(json) as AccessTokenClaims;
  } catch {
    return null;
  }
}

/**
 * True when the token is past its exp, with a small margin so a request is not
 * sent with a token that expires while it is in flight. The server applies its
 * own 45s clock skew allowance on top of this.
 */
export function isExpired(claims: AccessTokenClaims | null, marginSeconds = 20): boolean {
  if (!claims) {
    return true;
  }
  return claims.exp * 1000 - marginSeconds * 1000 <= Date.now();
}
