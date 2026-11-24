package com.iamplatform.user;

import com.iamplatform.auth.dto.MessageResponse;
import com.iamplatform.common.PageResponse;
import com.iamplatform.common.RequestMetadata;
import com.iamplatform.user.dto.AssignRolesRequest;
import com.iamplatform.user.dto.CreateUserRequest;
import com.iamplatform.user.dto.UpdateEmailRequest;
import com.iamplatform.user.dto.UpdateStatusRequest;
import com.iamplatform.user.dto.UserResponse;
import com.iamplatform.security.IamUserPrincipal;
import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.tags.Tag;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.validation.Valid;
import java.util.UUID;
import org.springframework.data.domain.Pageable;
import org.springframework.data.web.PageableDefault;
import org.springframework.http.HttpStatus;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.DeleteMapping;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.PutMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.ResponseStatus;
import org.springframework.web.bind.annotation.RestController;

/**
 * User profile and administration endpoints.
 *
 * <p>Authorization is expressed per method rather than by URL pattern, so reading
 * this file tells you exactly what each operation demands. Where an operation is
 * legitimate both for an administrator and for the account owner, the expression says
 * so explicitly instead of relying on a wider permission.
 */
@RestController
@RequestMapping("/users")
@Tag(name = "Users")
public class UserController {

    private final UserService userService;

    public UserController(UserService userService) {
        this.userService = userService;
    }

    @GetMapping("/me")
    @PreAuthorize("isAuthenticated()")
    @Operation(summary = "Profile of the signed-in user")
    public UserResponse me() {
        return userService.getCurrent();
    }

    @PutMapping("/me/email")
    @PreAuthorize("isAuthenticated()")
    @Operation(summary = "Change your own email address",
            description = "The new address starts unverified and every session is revoked.")
    public UserResponse updateOwnEmail(@Valid @RequestBody UpdateEmailRequest request,
            HttpServletRequest httpRequest) {
        return userService.updateEmail(IamUserPrincipal.requireUserId(), request.email(),
                RequestMetadata.from(httpRequest));
    }

    @GetMapping("/{id}")
    @PreAuthorize("hasAuthority('USER_READ') or #id == authentication.principal.userId()")
    @Operation(summary = "Read a user")
    public UserResponse getById(@PathVariable UUID id) {
        return userService.getById(id);
    }

    @GetMapping
    @PreAuthorize("hasAuthority('USER_READ')")
    @Operation(summary = "Search users")
    public PageResponse<UserResponse> search(@RequestParam(required = false) String query,
            @RequestParam(required = false) UserStatus status,
            @PageableDefault(size = 25) Pageable pageable) {
        return userService.search(query, status, pageable);
    }

    @PostMapping
    @PreAuthorize("hasAuthority('USER_CREATE')")
    @ResponseStatus(HttpStatus.CREATED)
    @Operation(summary = "Create a user administratively")
    public UserResponse create(@Valid @RequestBody CreateUserRequest request, HttpServletRequest httpRequest) {
        return userService.create(request, RequestMetadata.from(httpRequest));
    }

    @PutMapping("/{id}/email")
    @PreAuthorize("hasAuthority('USER_UPDATE')")
    @Operation(summary = "Change a user email address")
    public UserResponse updateEmail(@PathVariable UUID id, @Valid @RequestBody UpdateEmailRequest request,
            HttpServletRequest httpRequest) {
        return userService.updateEmail(id, request.email(), RequestMetadata.from(httpRequest));
    }

    @PutMapping("/{id}/status")
    @PreAuthorize("hasAuthority('USER_UPDATE')")
    @Operation(summary = "Enable or disable a user")
    public UserResponse updateStatus(@PathVariable UUID id, @Valid @RequestBody UpdateStatusRequest request,
            HttpServletRequest httpRequest) {
        return userService.changeStatus(id, request.status(), RequestMetadata.from(httpRequest));
    }

    @PutMapping("/{id}/roles")
    @PreAuthorize("hasAuthority('USER_UPDATE')")
    @Operation(summary = "Replace the roles assigned to a user",
            description = "Takes effect immediately: existing tokens for the user stop being accepted.")
    public UserResponse assignRoles(@PathVariable UUID id, @Valid @RequestBody AssignRolesRequest request,
            HttpServletRequest httpRequest) {
        return userService.assignRoles(id, request.roleIds(), RequestMetadata.from(httpRequest));
    }

    @PostMapping("/{id}/unlock")
    @PreAuthorize("hasAuthority('USER_UPDATE')")
    @Operation(summary = "Clear a brute-force lockout")
    public MessageResponse unlock(@PathVariable UUID id, HttpServletRequest httpRequest) {
        userService.unlock(id, RequestMetadata.from(httpRequest));
        return new MessageResponse("Account unlocked.");
    }

    @DeleteMapping("/{id}")
    @PreAuthorize("hasAuthority('USER_DELETE')")
    @ResponseStatus(HttpStatus.NO_CONTENT)
    @Operation(summary = "Delete a user",
            description = "Soft delete: personal data is scrubbed, the audit trail is retained.")
    public void delete(@PathVariable UUID id, HttpServletRequest httpRequest) {
        userService.delete(id, RequestMetadata.from(httpRequest));
    }
}
