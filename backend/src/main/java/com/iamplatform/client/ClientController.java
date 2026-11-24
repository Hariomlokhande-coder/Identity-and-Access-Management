package com.iamplatform.client;

import com.iamplatform.client.dto.ClientCredentialsResponse;
import com.iamplatform.client.dto.ClientResponse;
import com.iamplatform.client.dto.CreateClientRequest;
import com.iamplatform.client.dto.UpdateClientRequest;
import com.iamplatform.common.PageResponse;
import com.iamplatform.common.RequestMetadata;
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
import org.springframework.web.bind.annotation.ResponseStatus;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/clients")
@Tag(name = "Client applications")
public class ClientController {

    private final ClientService clientService;

    public ClientController(ClientService clientService) {
        this.clientService = clientService;
    }

    @GetMapping
    @PreAuthorize("hasAuthority('CLIENT_READ')")
    @Operation(summary = "List registered applications")
    public PageResponse<ClientResponse> list(@PageableDefault(size = 25) Pageable pageable) {
        return clientService.list(pageable);
    }

    @GetMapping("/{id}")
    @PreAuthorize("hasAuthority('CLIENT_READ')")
    @Operation(summary = "Read one application")
    public ClientResponse get(@PathVariable UUID id) {
        return clientService.get(id);
    }

    @PostMapping
    @PreAuthorize("hasAuthority('CLIENT_MANAGE')")
    @ResponseStatus(HttpStatus.CREATED)
    @Operation(summary = "Register an application",
            description = "The client secret is returned here and never again.")
    public ClientCredentialsResponse create(@Valid @RequestBody CreateClientRequest request,
            HttpServletRequest httpRequest) {
        return clientService.create(request, RequestMetadata.from(httpRequest));
    }

    @PutMapping("/{id}")
    @PreAuthorize("hasAuthority('CLIENT_MANAGE')")
    @Operation(summary = "Update an application")
    public ClientResponse update(@PathVariable UUID id, @Valid @RequestBody UpdateClientRequest request,
            HttpServletRequest httpRequest) {
        return clientService.update(id, request, RequestMetadata.from(httpRequest));
    }

    @PostMapping("/{id}/rotate-secret")
    @PreAuthorize("hasAuthority('CLIENT_MANAGE')")
    @Operation(summary = "Issue a new client secret, invalidating the current one")
    public ClientCredentialsResponse rotateSecret(@PathVariable UUID id, HttpServletRequest httpRequest) {
        return clientService.rotateSecret(id, RequestMetadata.from(httpRequest));
    }

    @DeleteMapping("/{id}")
    @PreAuthorize("hasAuthority('CLIENT_MANAGE')")
    @ResponseStatus(HttpStatus.NO_CONTENT)
    @Operation(summary = "Delete an application and everything scoped to it")
    public void delete(@PathVariable UUID id, HttpServletRequest httpRequest) {
        clientService.delete(id, RequestMetadata.from(httpRequest));
    }
}
