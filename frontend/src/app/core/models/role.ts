export interface RoleResponse {
  id: string;
  name: string;
  description: string | null;
  /** null for a platform-wide role; set when the role is scoped to one client. */
  clientId: string | null;
  /** System roles cannot be deleted. */
  systemRole: boolean;
  permissions: string[];
}

export interface PermissionResponse {
  id: string;
  name: string;
  description: string | null;
}

export interface CreateRoleRequest {
  /** Server-side pattern: [A-Z][A-Z0-9_]* */
  name: string;
  description?: string;
  clientId?: string;
  permissions?: string[];
}

export interface UpdateRoleRequest {
  description?: string;
  permissions: string[];
}

/** Same rule as CreateRoleRequest's @Pattern, so the UI fails before the round trip. */
export const ROLE_NAME_PATTERN = /^[A-Z][A-Z0-9_]*$/;
