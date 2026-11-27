/** GET /oauth2/consent?request_id=... — what the consent screen has to describe. */
export interface PendingAuthorization {
  requestId: string;
  clientId: string;
  clientName: string;
  scopes: string[];
}

export interface ConsentDecisionRequest {
  requestId: string;
  approved: boolean;
}

/** GET /oauth2/consents — applications this user has already granted access to. */
export interface GrantedConsent {
  /** The internal id, and the only one DELETE /oauth2/consents/{id} accepts. */
  clientApplicationId: string;
  /** The public OAuth client_id, shown so a grant can be matched to a client. */
  clientId: string;
  clientName: string;
  scopes: string[];
  grantedAt: string;
}
