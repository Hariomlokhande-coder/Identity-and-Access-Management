export type ClientType = 'PUBLIC' | 'CONFIDENTIAL';
export type ClientStatus = 'ACTIVE' | 'DISABLED';

export interface ClientResponse {
  id: string;
  clientId: string;
  name: string;
  clientType: ClientType;
  status: ClientStatus;
  requireConsent: boolean;
  requirePkce: boolean;
  redirectUris: string[];
  scopes: string[];
  accessTokenTtlSeconds: number | null;
  refreshTokenTtlSeconds: number | null;
  createdAt: string;
}

/**
 * The only response that ever carries a client secret. The server stores a hash,
 * so this is the one moment the plaintext exists anywhere the UI can show it.
 */
export interface ClientCredentialsResponse {
  client: ClientResponse;
  clientSecret?: string;
  notice: string;
}

export interface CreateClientRequest {
  name: string;
  clientType: ClientType;
  redirectUris: string[];
  scopes?: string[];
  requireConsent?: boolean;
  requirePkce?: boolean;
  accessTokenTtlSeconds?: number;
  refreshTokenTtlSeconds?: number;
}

export interface UpdateClientRequest {
  name: string;
  status: ClientStatus;
  redirectUris: string[];
  scopes?: string[];
  requireConsent?: boolean;
  requirePkce?: boolean;
  accessTokenTtlSeconds?: number;
  refreshTokenTtlSeconds?: number;
}
