export interface SessionResponse {
  id: string;
  clientId: string | null;
  deviceInfo: string | null;
  ipAddress: string | null;
  createdAt: string;
  lastSeenAt: string | null;
  expiresAt: string;
  /** True for the session the current access token belongs to. */
  current: boolean;
}
