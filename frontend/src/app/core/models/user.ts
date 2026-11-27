export type UserStatus = 'PENDING_VERIFICATION' | 'ACTIVE' | 'DISABLED' | 'DELETED';

export const USER_STATUSES: UserStatus[] = ['PENDING_VERIFICATION', 'ACTIVE', 'DISABLED', 'DELETED'];

export interface UserResponse {
  id: string;
  email: string;
  status: UserStatus;
  emailVerified: boolean;
  roles: string[];
  createdAt: string;
  lastLoginAt: string | null;
  lockedUntil: string | null;
}

export interface CreateUserRequest {
  email: string;
  password: string;
  roleIds?: string[];
  emailVerified: boolean;
}

export interface UpdateEmailRequest {
  email: string;
}

export interface UpdateStatusRequest {
  status: UserStatus;
}

export interface AssignRolesRequest {
  roleIds: string[];
}

export interface UserSearchQuery {
  query?: string;
  status?: UserStatus;
}
