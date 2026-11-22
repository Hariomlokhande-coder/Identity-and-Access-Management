package com.example.iam.role;

import com.example.iam.common.RequestMetadata;
import com.example.iam.role.dto.CreateRoleRequest;
import com.example.iam.role.dto.PermissionResponse;
import com.example.iam.role.dto.RoleResponse;
import com.example.iam.role.dto.UpdateRoleRequest;
import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.tags.Tag;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.validation.Valid;
import java.util.List;
import java.util.UUID;
import org.springframework.http.HttpStatus;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.DeleteMapping;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.PutMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.ResponseStatus;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/roles")
@Tag(name = "Roles and permissions")
public class RoleController {

    private final RoleService roleService;

    public RoleController(RoleService roleService) {
        this.roleService = roleService;
    }

    @GetMapping
    @PreAuthorize("hasAuthority('ROLE_READ')")
    @Operation(summary = "List roles with their permissions")
    public List<RoleResponse> list() {
        return roleService.list();
    }

    @GetMapping("/{id}")
    @PreAuthorize("hasAuthority('ROLE_READ')")
    @Operation(summary = "Read a role")
    public RoleResponse get(@PathVariable UUID id) {
        return roleService.get(id);
    }

    @PostMapping
    @PreAuthorize("hasAuthority('ROLE_MANAGE')")
    @ResponseStatus(HttpStatus.CREATED)
    @Operation(summary = "Create a role",
            description = "Scope it to a client unless it is genuinely platform-wide.")
    public RoleResponse create(@Valid @RequestBody CreateRoleRequest request, HttpServletRequest httpRequest) {
        return roleService.create(request, RequestMetadata.from(httpRequest));
    }

    @PutMapping("/{id}/permissions")
    @PreAuthorize("hasAuthority('ROLE_MANAGE')")
    @Operation(summary = "Replace the permissions of a role",
            description = "Holders lose or gain the authority immediately; their current tokens stop working.")
    public RoleResponse updatePermissions(@PathVariable UUID id, @Valid @RequestBody UpdateRoleRequest request,
            HttpServletRequest httpRequest) {
        return roleService.update(id, request, RequestMetadata.from(httpRequest));
    }

    @DeleteMapping("/{id}")
    @PreAuthorize("hasAuthority('ROLE_MANAGE')")
    @ResponseStatus(HttpStatus.NO_CONTENT)
    @Operation(summary = "Delete a non-system role")
    public void delete(@PathVariable UUID id, HttpServletRequest httpRequest) {
        roleService.delete(id, RequestMetadata.from(httpRequest));
    }

    @GetMapping("/permissions")
    @PreAuthorize("hasAuthority('ROLE_READ')")
    @Operation(summary = "List the permissions this platform enforces")
    public List<PermissionResponse> listPermissions() {
        return roleService.listPermissions();
    }
}
