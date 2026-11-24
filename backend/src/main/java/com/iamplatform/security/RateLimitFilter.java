package com.iamplatform.security;

import com.iamplatform.common.RequestMetadata;
import com.iamplatform.config.IamProperties;
import com.iamplatform.config.IamProperties.RateLimit.KeyType;
import com.iamplatform.config.IamProperties.RateLimit.Rule;
import com.iamplatform.exception.ApiException;
import com.iamplatform.exception.ErrorCode;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.util.Map;
import java.util.Optional;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.stereotype.Component;
import org.springframework.util.AntPathMatcher;
import org.springframework.web.filter.OncePerRequestFilter;
import org.springframework.web.servlet.HandlerExceptionResolver;

/**
 * Applies the configured rate-limit rules. First matching rule wins, so specific
 * paths are listed before the catch-all in configuration.
 *
 * <p>It runs just after token authentication so a rule can bucket per user rather
 * than per address - otherwise everyone behind one NAT would share an allowance, and
 * one noisy tenant could throttle the rest. Anonymous traffic, which is most of what
 * needs throttling, still falls back to the source address.
 */
@Component
public class RateLimitFilter extends OncePerRequestFilter {

    private static final Logger log = LoggerFactory.getLogger(RateLimitFilter.class);

    private final AntPathMatcher pathMatcher = new AntPathMatcher();
    private final RateLimiter rateLimiter;
    private final IamProperties properties;
    private final HandlerExceptionResolver exceptionResolver;

    public RateLimitFilter(RateLimiter rateLimiter, IamProperties properties,
            @Qualifier("handlerExceptionResolver") HandlerExceptionResolver exceptionResolver) {
        this.rateLimiter = rateLimiter;
        this.properties = properties;
        this.exceptionResolver = exceptionResolver;
    }

    @Override
    protected boolean shouldNotFilter(HttpServletRequest request) {
        return !properties.getRateLimit().isEnabled();
    }

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain chain)
            throws ServletException, IOException {
        Optional<Rule> rule = matchingRule(request);
        if (rule.isEmpty()) {
            chain.doFilter(request, response);
            return;
        }

        Rule matched = rule.get();
        try {
            RateLimiter.Decision decision = rateLimiter.check(matched.getPath(), identityFor(request, matched),
                    matched.getLimit(), matched.getWindow());
            response.setHeader("X-RateLimit-Limit", Integer.toString(matched.getLimit()));
            response.setHeader("X-RateLimit-Remaining", Long.toString(decision.remaining()));

            if (!decision.allowed()) {
                reject(request, response, matched, decision);
                return;
            }
        } catch (ApiException e) {
            exceptionResolver.resolveException(request, response, null, e);
            return;
        }
        chain.doFilter(request, response);
    }

    private void reject(HttpServletRequest request, HttpServletResponse response, Rule rule,
            RateLimiter.Decision decision) {
        log.warn("Rate limit hit for {} {} (limit {} per {})", request.getMethod(), rule.getPath(),
                rule.getLimit(), rule.getWindow());
        response.setHeader("Retry-After", Long.toString(decision.retryAfterSeconds()));
        ApiException exception = new ApiException(ErrorCode.RATE_LIMITED, ErrorCode.RATE_LIMITED.defaultMessage(),
                Map.of("retryAfterSeconds", decision.retryAfterSeconds()));
        exceptionResolver.resolveException(request, response, null, exception);
    }

    private Optional<Rule> matchingRule(HttpServletRequest request) {
        String path = request.getRequestURI();
        String method = request.getMethod();
        return properties.getRateLimit().getRules().stream()
                .filter(rule -> pathMatcher.match(rule.getPath(), path))
                .filter(rule -> rule.getMethods().isEmpty() || rule.getMethods().contains(method))
                .findFirst();
    }

    /**
     * Anonymous traffic is bucketed by source address. Authenticated traffic is
     * bucketed per user where the rule asks for it, so one noisy client cannot exhaust
     * the shared allowance of everyone behind the same NAT.
     */
    private String identityFor(HttpServletRequest request, Rule rule) {
        String ip = RequestMetadata.from(request).ipAddress();
        if (rule.getKey() != KeyType.PRINCIPAL_OR_IP) {
            return ip;
        }
        return IamUserPrincipal.current().map(principal -> "user:" + principal.userId()).orElse(ip);
    }
}
