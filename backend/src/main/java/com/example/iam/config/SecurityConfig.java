package com.example.iam.config;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;

/**
 * STARTER VERSION - Phase 16 replaces this whole file.
 *
 * <p>Two jobs until then. First, PasswordService needs a PasswordEncoder bean, and
 * without one the application would not even start. Second, the real filter chain
 * needs three filters that do not exist yet, so for now every request is let through.
 * That is only acceptable because nothing here is deployed: it is a scaffold for
 * building, not a security configuration.
 */
@Configuration
public class SecurityConfig {

    private final IamProperties properties;

    public SecurityConfig(IamProperties properties) {
        this.properties = properties;
    }

    /** Identical to the final version, so hashes written now stay valid later. */
    @Bean
    public PasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder(properties.getPassword().getBcryptStrength());
    }

    @Bean
    public SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
        http
                .csrf(csrf -> csrf.disable())
                .sessionManagement(session -> session.sessionCreationPolicy(SessionCreationPolicy.STATELESS))
                .authorizeHttpRequests(requests -> requests.anyRequest().permitAll());
        return http.build();
    }
}