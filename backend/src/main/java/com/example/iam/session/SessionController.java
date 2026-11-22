package com.example.iam.session;

import com.example.iam.auth.dto.MessageResponse;
import com.example.iam.common.RequestMetadata;
import com.example.iam.security.IamUserPrincipal;
import com.example.iam.session.dto.SessionResponse;
import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.tags.Tag;
import jakarta.servlet.http.HttpServletRequest;
import java.util.List;
import java.util.UUID;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.DeleteMapping;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

/**
 * Device session management.
 *
 * <p>Every endpoint here operates on the caller's own sessions, taken from the
 * authenticated principal rather than from a path parameter. Letting a client name
 * the user whose sessions to end would be an authorization bug waiting to happen;
 * administrative revocation is a separate, permission-gated endpoint.
 */
@RestController
@RequestMapping("/sessions")
@Tag(name = "Sessions")
public class SessionController {

    private final SessionService sessionService;

    public SessionController(SessionService sessionService) {
        this.sessionService = sessionService;
    }

    @GetMapping
    @PreAuthorize("isAuthenticated()")
    @Operation(summary = "List your active sessions")
    public List<SessionResponse> list() {
        IamUserPrincipal principal = IamUserPrincipal.require();
        return sessionService.listActive(principal.userId()).stream()
                .map(session -> SessionResponse.from(session, principal.sessionId()))
                .toList();
    }

    @DeleteMapping("/all")
    @PreAuthorize("isAuthenticated()")
    @Operation(summary = "Sign out of every other device",
            description = "The current session is kept so the caller is not signed out of the page they are on.")
    public MessageResponse revokeAll() {
        IamUserPrincipal principal = IamUserPrincipal.require();
        int revoked = sessionService.revokeAll(principal.userId(), principal.sessionId(), "user_revoked_all");
        return new MessageResponse("Signed out of " + revoked + " other session(s).");
    }

    @DeleteMapping("/{id}")
    @PreAuthorize("isAuthenticated()")
    @Operation(summary = "Revoke one of your sessions")
    public MessageResponse revoke(@PathVariable UUID id, HttpServletRequest httpRequest) {
        sessionService.revokeOwn(IamUserPrincipal.requireUserId(), id, RequestMetadata.from(httpRequest));
        return new MessageResponse("Session revoked.");
    }

    @DeleteMapping("/users/{userId}")
    @PreAuthorize("hasAuthority('SESSION_ADMIN')")
    @Operation(summary = "Administratively sign a user out everywhere")
    public MessageResponse revokeForUser(@PathVariable UUID userId) {
        int revoked = sessionService.revokeAll(userId, null, "admin_revoked");
        return new MessageResponse("Revoked " + revoked + " session(s).");
    }
}
