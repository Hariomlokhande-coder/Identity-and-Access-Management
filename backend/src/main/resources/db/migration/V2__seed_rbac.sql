-- Platform-level permissions and the three baseline roles from the design doc.
-- Idempotent so the migration is safe to re-run against a partially seeded DB.

INSERT INTO permissions (name, description) VALUES
('USER_READ', 'Read any user profile'),
('USER_CREATE', 'Create users'),
('USER_UPDATE', 'Update any user'),
('USER_DELETE', 'Delete any user'),
('PROFILE_READ', 'Read own profile'),
('PROFILE_UPDATE', 'Update own profile'),
('ROLE_READ', 'Read roles and permissions'),
('ROLE_MANAGE', 'Create, update and delete roles'),
('CLIENT_READ', 'Read registered client applications'),
('CLIENT_MANAGE', 'Register and manage client applications'),
('SESSION_ADMIN', 'List and revoke sessions of any user'),
('AUDIT_READ', 'Read the security audit trail')
ON CONFLICT (name) DO NOTHING;

INSERT INTO roles (name, description, system_role) VALUES
('ADMIN', 'Full platform administration', TRUE),
('MANAGER', 'Read and update users', TRUE),
('USER', 'Standard end user', TRUE)
ON CONFLICT DO NOTHING;

INSERT INTO role_permissions (role_id, permission_id)
SELECT r.id, p.id FROM roles r, permissions p
WHERE r.client_application_id IS NULL AND (
    (r.name = 'ADMIN')
    OR (r.name = 'MANAGER' AND p.name IN ('USER_READ', 'USER_UPDATE', 'PROFILE_READ', 'PROFILE_UPDATE'))
    OR (r.name = 'USER' AND p.name IN ('PROFILE_READ', 'PROFILE_UPDATE'))
)
ON CONFLICT DO NOTHING;