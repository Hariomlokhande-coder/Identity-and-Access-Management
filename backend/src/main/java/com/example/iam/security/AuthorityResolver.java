package com.example.iam.security;

import com.example.iam.role.Permission;
import com.example.iam.role.Role;
import com.example.iam.user.User;
import java.util.Collection;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Set;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.stereotype.Component;

/**
 * Turns a user's role assignments into the authorities that apply for one audience.
 *
 * <p>Scoping happens here and nowhere else. A role attached to a client application
 * is invisible to every other application, so an "ADMIN" of the shop can never act as
 * an admin of the bank just because both delegate identity to this platform. Platform
 * roles (no client) apply everywhere, including to this platform's own API.
 */
@Component
public class AuthorityResolver {

    private static final String ROLE_PREFIX = "ROLE_";

    public ResolvedAuthorities resolve(User user, String audience) {
        Set<String> roles = new LinkedHashSet<>();
        Set<String> permissions = new LinkedHashSet<>();

        for (Role role : user.getRoles()) {
            if (!role.appliesTo(audience)) {
                continue;
            }
            roles.add(role.getName());
            for (Permission permission : role.getPermissions()) {
                // Permissions merge across every role the user holds: holding two roles
                // grants the union, never the intersection.
                permissions.add(permission.getName());
            }
        }
        return new ResolvedAuthorities(roles, permissions);
    }

    /**
     * Roles and permissions of one caller for one audience.
     *
     * <p>Both are exposed as Spring authorities: roles with the conventional
     * {@code ROLE_} prefix so {@code hasRole} works, permissions bare so
     * {@code hasAuthority('USER_READ')} works.
     */
    public record ResolvedAuthorities(Set<String> roles, Set<String> permissions) {

        public static final ResolvedAuthorities EMPTY = new ResolvedAuthorities(Set.of(), Set.of());

        public Collection<GrantedAuthority> toGrantedAuthorities() {
            List<GrantedAuthority> authorities = new java.util.ArrayList<>(roles.size() + permissions.size());
            roles.forEach(role -> authorities.add(new SimpleGrantedAuthority(ROLE_PREFIX + role)));
            permissions.forEach(permission -> authorities.add(new SimpleGrantedAuthority(permission)));
            return authorities;
        }

        public static Collection<GrantedAuthority> toGrantedAuthorities(Set<String> roles, Set<String> permissions) {
            return new ResolvedAuthorities(roles, permissions).toGrantedAuthorities();
        }
    }
}
