package io.github.hariomlokhande.iam.config;

import io.github.hariomlokhande.iam.exception.ApiException;
import io.github.hariomlokhande.iam.exception.ErrorCode;
import io.github.hariomlokhande.iam.security.JwtAuthenticationFilter;
import io.github.hariomlokhande.iam.security.RateLimitFilter;
import io.github.hariomlokhande.iam.security.SsoSessionAuthenticationFilter;
import jakarta.servlet.Filter;
import java.util.List;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.boot.web.servlet.FilterRegistrationBean;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.HttpMethod;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.method.configuration.EnableMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import org.springframework.web.cors.CorsConfiguration;
import org.springframework.web.cors.CorsConfigurationSource;
import org.springframework.web.cors.UrlBasedCorsConfigurationSource;
import org.springframework.web.servlet.HandlerExceptionResolver;

/**
 * The security filter chain.
 *
 * <p>Everything is denied unless listed. The permitted set is short and deliberate:
 * the flows a caller must be able to reach before they hold any credential, plus the
 * OAuth2 endpoints that authenticate themselves.
 *
 * <p>CSRF protection is not switched off so much as achieved differently. The API is
 * stateless and authenticated by a bearer token, which a third-party page cannot
 * attach. The one cookie-authenticated endpoint - the consent decision - is protected
 * by SameSite=Lax on that cookie, which stops it being sent on a cross-site POST at
 * all, and by requiring a JSON body, which a plain HTML form cannot produce.
 */
@Configuration
@EnableMethodSecurity
public class SecurityConfig {

    /** Reachable without any credential. */
    private static final String[] PUBLIC_ENDPOINTS = {
        "/auth/register",
        "/auth/login",
        "/auth/refresh",
        "/auth/verify-email",
        "/auth/resend-verification",
        "/auth/forgot-password",
        "/auth/reset-password",
        "/oauth2/authorize",
        "/oauth2/token",
        "/oauth2/jwks",
        "/oauth2/userinfo",
        "/.well-known/**",
        "/actuator/health",
        "/actuator/health/**",
        "/actuator/info",
        "/v3/api-docs/**",
        "/swagger-ui/**",
        "/swagger-ui.html"
    };

    private final IamProperties properties;

    public SecurityConfig(IamProperties properties) {
        this.properties = properties;
    }

    /**
     * BCrypt at a configurable cost. The cost is deliberately a setting: it has to be
     * raised over the years as hardware gets faster, and that must not need a code
     * change.
     */
    @Bean
    public PasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder(properties.getPassword().getBcryptStrength());
    }

    @Bean
    public SecurityFilterChain filterChain(HttpSecurity http, JwtAuthenticationFilter jwtFilter,
            SsoSessionAuthenticationFilter ssoFilter, RateLimitFilter rateLimitFilter,
            @Qualifier("handlerExceptionResolver") HandlerExceptionResolver exceptionResolver) throws Exception {

        http
            .csrf(csrf -> csrf.disable())
            .cors(Customizer.withDefaults())
            .sessionManagement(session -> session.sessionCreationPolicy(SessionCreationPolicy.STATELESS))
            .headers(headers -> headers
                    .frameOptions(frame -> frame.deny())
                    .contentTypeOptions(Customizer.withDefaults())
                    .referrerPolicy(referrer -> referrer.policy(
                            org.springframework.security.web.header.writers.ReferrerPolicyHeaderWriter
                                    .ReferrerPolicy.NO_REFERRER))
                    .httpStrictTransportSecurity(hsts -> hsts
                            .includeSubDomains(true)
                            .maxAgeInSeconds(31536000)))
            .authorizeHttpRequests(requests -> requests
                    .requestMatchers(HttpMethod.OPTIONS, "/**").permitAll()
                    .requestMatchers(PUBLIC_ENDPOINTS).permitAll()
                    .anyRequest().authenticated())
            // Both rejections are routed through the same resolver as everything else,
            // so a 401 from the filter chain is indistinguishable in shape from a 401
            // raised inside a service.
            .exceptionHandling(handling -> handling
                    .authenticationEntryPoint((request, response, exception) ->
                            exceptionResolver.resolveException(request, response, null,
                                    new ApiException(ErrorCode.UNAUTHENTICATED,
                                            ErrorCode.UNAUTHENTICATED.defaultMessage())))
                    .accessDeniedHandler((request, response, exception) ->
                            exceptionResolver.resolveException(request, response, null,
                                    new ApiException(ErrorCode.FORBIDDEN,
                                            ErrorCode.FORBIDDEN.defaultMessage()))))
            .addFilterBefore(jwtFilter, UsernamePasswordAuthenticationFilter.class)
            .addFilterAfter(ssoFilter, JwtAuthenticationFilter.class)
            // Last of the three: a per-user rate limit needs the principal to exist.
            .addFilterAfter(rateLimitFilter, SsoSessionAuthenticationFilter.class);

        return http.build();
    }

    /**
     * Keeps the security filters out of the plain servlet chain.
     *
     * <p>Spring Boot registers every {@code Filter} bean as a servlet filter, so a
     * filter that is also placed in the security chain would appear twice. It would
     * still behave correctly - {@code OncePerRequestFilter} sees its own marker and
     * skips the second pass - but it would also run for requests the security chain
     * never handled, which is not what any of these three filters are written for.
     */
    @Bean
    public FilterRegistrationBean<JwtAuthenticationFilter> jwtFilterRegistration(
            JwtAuthenticationFilter filter) {
        return securityChainOnly(filter);
    }

    @Bean
    public FilterRegistrationBean<SsoSessionAuthenticationFilter> ssoFilterRegistration(
            SsoSessionAuthenticationFilter filter) {
        return securityChainOnly(filter);
    }

    @Bean
    public FilterRegistrationBean<RateLimitFilter> rateLimitFilterRegistration(RateLimitFilter filter) {
        return securityChainOnly(filter);
    }

    private <T extends Filter> FilterRegistrationBean<T> securityChainOnly(T filter) {
        FilterRegistrationBean<T> registration = new FilterRegistrationBean<>(filter);
        registration.setEnabled(false);
        return registration;
    }

    /**
     * CORS is configured from an explicit origin list. A wildcard would let any site
     * read authenticated responses, and is never appropriate for an identity provider.
     */
    @Bean
    public CorsConfigurationSource corsConfigurationSource() {
        IamProperties.Cors cors = properties.getCors();
        CorsConfiguration configuration = new CorsConfiguration();
        configuration.setAllowedOrigins(cors.getAllowedOrigins());
        configuration.setAllowedMethods(List.of("GET", "POST", "PUT", "DELETE", "OPTIONS"));
        configuration.setAllowedHeaders(cors.getAllowedHeaders());
        configuration.setExposedHeaders(List.of("X-Correlation-Id", "Retry-After"));
        configuration.setAllowCredentials(true);
        configuration.setMaxAge(cors.getMaxAge());

        UrlBasedCorsConfigurationSource source = new UrlBasedCorsConfigurationSource();
        source.registerCorsConfiguration("/**", configuration);
        return source;
    }
}
