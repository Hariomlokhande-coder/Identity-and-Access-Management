package com.example.iam.security;

import static org.assertj.core.api.Assertions.assertThat;

import com.example.iam.auth.token.JwtService;
import com.example.iam.client.ClientApplication;
import com.example.iam.role.Permission;
import com.example.iam.role.Role;
import com.example.iam.security.AuthorityResolver.ResolvedAuthorities;
import com.example.iam.user.User;
import java.util.UUID;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.security.core.GrantedAuthority;

class AuthorityResolverTest {

    private final AuthorityResolver resolver = new AuthorityResolver();

    @Test
    @DisplayName("merges the permissions of every role the user holds")
    void mergesPermissionsAcrossRoles() {
        User user = user(platformRole("MANAGER", "USER_READ", "USER_UPDATE"),
                platformRole("AUDITOR", "USER_READ", "AUDIT_READ"));

        ResolvedAuthorities authorities = resolver.resolve(user, JwtService.PLATFORM_AUDIENCE);

        assertThat(authorities.roles()).containsExactlyInAnyOrder("MANAGER", "AUDITOR");
        assertThat(authorities.permissions())
                .containsExactlyInAnyOrder("USER_READ", "USER_UPDATE", "AUDIT_READ");
    }

    /**
     * The cross-application leak the design warns about: being an admin of one client
     * must grant nothing at all in another.
     */
    @Test
    @DisplayName("a role scoped to one client is invisible to another client")
    void scopedRolesDoNotLeakAcrossClients() {
        User user = user(scopedRole("shop", "SHOP_ADMIN", "ORDER_WRITE"),
                scopedRole("bank", "BANK_VIEWER", "ACCOUNT_READ"));

        ResolvedAuthorities forShop = resolver.resolve(user, "shop");

        assertThat(forShop.roles()).containsExactly("SHOP_ADMIN");
        assertThat(forShop.permissions()).containsExactly("ORDER_WRITE");
        assertThat(forShop.permissions()).doesNotContain("ACCOUNT_READ");
    }

    @Test
    @DisplayName("a platform role applies in every audience, including the platform API")
    void platformRolesApplyEverywhere() {
        User user = user(platformRole("ADMIN", "USER_READ"), scopedRole("shop", "SHOP_ADMIN", "ORDER_WRITE"));

        assertThat(resolver.resolve(user, "bank").roles()).containsExactly("ADMIN");
        assertThat(resolver.resolve(user, JwtService.PLATFORM_AUDIENCE).roles()).containsExactly("ADMIN");
    }

    @Test
    @DisplayName("roles get the ROLE_ prefix as Spring expects, permissions do not")
    void mapsToSpringAuthorities() {
        User user = user(platformRole("ADMIN", "USER_READ"));

        assertThat(resolver.resolve(user, JwtService.PLATFORM_AUDIENCE).toGrantedAuthorities())
                .extracting(GrantedAuthority::getAuthority)
                .containsExactlyInAnyOrder("ROLE_ADMIN", "USER_READ");
    }

    @Test
    @DisplayName("a user with no roles gets no authorities")
    void handlesUserWithoutRoles() {
        assertThat(resolver.resolve(user(), JwtService.PLATFORM_AUDIENCE).toGrantedAuthorities()).isEmpty();
    }

    private User user(Role... roles) {
        User user = new User();
        user.setId(UUID.randomUUID());
        for (Role role : roles) {
            user.getRoles().add(role);
        }
        return user;
    }

    private Role platformRole(String name, String... permissions) {
        return role(name, null, permissions);
    }

    private Role scopedRole(String clientId, String name, String... permissions) {
        ClientApplication client = new ClientApplication();
        client.setId(UUID.randomUUID());
        client.setClientId(clientId);
        return role(name, client, permissions);
    }

    private Role role(String name, ClientApplication client, String... permissionNames) {
        Role role = new Role();
        role.setId(UUID.randomUUID());
        role.setName(name);
        role.setClientApplication(client);
        for (String permissionName : permissionNames) {
            Permission permission = new Permission();
            permission.setId(UUID.randomUUID());
            permission.setName(permissionName);
            role.getPermissions().add(permission);
        }
        return role;
    }
}
