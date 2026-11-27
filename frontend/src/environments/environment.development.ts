export const environment = {
  production: false,
  /**
   * The backend's default issuer. The dev server runs on port 3001 because that is
   * the only origin iam.cors.allowed-origins permits out of the box, and credentials
   * (the SSO cookie) are only sent to an explicitly allowed origin.
   */
  apiBase: 'http://localhost:8081',
};
