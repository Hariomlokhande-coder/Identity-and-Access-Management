package com.example.iam.support;

import com.example.iam.config.IamProperties;
import java.time.Duration;

/** Builds an {@link IamProperties} with sane defaults for unit tests. */
public final class TestProperties {

    public static final String ISSUER = "https://auth.test.local";

    private TestProperties() {
    }

    public static IamProperties create() {
        IamProperties properties = new IamProperties();
        properties.setIssuer(ISSUER);
        properties.getJwt().setAllowEphemeralKey(true);
        properties.getJwt().setAccessTokenTtl(Duration.ofMinutes(10));
        properties.getJwt().setClockSkew(Duration.ofSeconds(30));
        return properties;
    }
}