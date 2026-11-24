package io.github.hariomlokhande.iam.config;

import io.swagger.v3.oas.models.Components;
import io.swagger.v3.oas.models.OpenAPI;
import io.swagger.v3.oas.models.info.Info;
import io.swagger.v3.oas.models.security.SecurityRequirement;
import io.swagger.v3.oas.models.security.SecurityScheme;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

/** API documentation, including how to authenticate against it. */
@Configuration
public class OpenApiConfig {

    private static final String BEARER_SCHEME = "bearerAuth";

    @Bean
    public OpenAPI iamOpenApi(IamProperties properties) {
        return new OpenAPI()
                .info(new Info()
                        .title("Identity and Access Management API")
                        .version("1.0.0")
                        .description("Centralised authentication, authorization and session management. "
                                + "Issuer: " + properties.getIssuer()))
                .components(new Components().addSecuritySchemes(BEARER_SCHEME, new SecurityScheme()
                        .type(SecurityScheme.Type.HTTP)
                        .scheme("bearer")
                        .bearerFormat("JWT")
                        .description("Access token from /auth/login or the OAuth2 token endpoint")))
                .addSecurityItem(new SecurityRequirement().addList(BEARER_SCHEME));
    }
}
