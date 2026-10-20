
package com.example.iam.auth.token;

import com.example.iam.config.IamProperties;
import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.KeyUse;
import com.nimbusds.jose.jwk.RSAKey;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.ArrayList;
import java.util.Base64;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Component;

@Component
public class SigningKeyStore {

    private static final Logger log = LoggerFactory.getLogger(SigningKeyStore.class);

    private final Map<String, RSAKey> keysByKid = new LinkedHashMap<>();
    private final RSAKey activeKey;
    private final JWKSet publicJwkSet;

    public SigningKeyStore(IamProperties properties, ObjectMapper objectMapper) {
        List<KeyDefinition> definitions = parse(properties.getJwt().getKeys(), objectMapper);
        RSAKey active = null;

        for (KeyDefinition definition : definitions) {
            RSAKey key = toRsaKey(definition);
            keysByKid.put(key.getKeyID(), key);
            if (definition.active() && active == null) {
                active = key;
            }
        }

        if (keysByKid.isEmpty()) {
            if (!properties.getJwt().isAllowEphemeralKey()) {
                throw new IllegalStateException(
                        "No JWT signing key configured. Set iam.jwt.keys (see scripts/generate-jwt-key.sh). "
                                + "Ephemeral keys are only allowed when iam.jwt.allow-ephemeral-key is true.");
            }
            active = generateEphemeralKey();
            keysByKid.put(active.getKeyID(), active);
            log.warn("Using an EPHEMERAL JWT signing key. Every restart invalidates all issued tokens "
                    + "and other instances cannot verify them. Never enable this outside local development.");
        } else if (active == null) {
            active = keysByKid.values().iterator().next();
            log.warn("No signing key marked active; defaulting to kid={}", active.getKeyID());
        }

        this.activeKey = active;
        this.publicJwkSet = new JWKSet(new ArrayList<>(keysByKid.values())).toPublicJWKSet();
        log.info("Loaded {} JWT signing key(s); active kid={}", keysByKid.size(), activeKey.getKeyID());
    }

    public RSAKey activeKey() {
        return activeKey;
    }

    public Optional<RSAKey> verificationKey(String kid) {
        return Optional.ofNullable(kid).map(keysByKid::get);
    }

    public Map<String, Object> jwks() {
        return publicJwkSet.toJSONObject();
    }

    private List<KeyDefinition> parse(String raw, ObjectMapper objectMapper) {
        if (raw == null || raw.isBlank()) {
            return List.of();
        }
        try {
            return objectMapper.readValue(raw, new TypeReference<List<KeyDefinition>>() {
            });
        } catch (Exception e) {
            throw new IllegalStateException("iam.jwt.keys is not a valid JSON array of signing keys", e);
        }
    }

    private RSAKey toRsaKey(KeyDefinition definition) {
        try {
            KeyFactory factory = KeyFactory.getInstance("RSA");
            RSAPublicKey publicKey = (RSAPublicKey) factory
                    .generatePublic(new X509EncodedKeySpec(decode(definition.publicKey())));
            RSAPrivateKey privateKey = (RSAPrivateKey) factory
                    .generatePrivate(new PKCS8EncodedKeySpec(decode(definition.privateKey())));
            return new RSAKey.Builder(publicKey)
                    .privateKey(privateKey)
                    .keyID(definition.kid())
                    .keyUse(KeyUse.SIGNATURE)
                    .algorithm(JWSAlgorithm.RS256)
                    .build();
        } catch (Exception e) {
            throw new IllegalStateException("Signing key '" + definition.kid() + "' could not be loaded", e);
        }
    }

    private byte[] decode(String material) {
        String cleaned = material.replaceAll("-----[A-Z ]+-----", "").replaceAll("\\s", "");
        return Base64.getDecoder().decode(cleaned);
    }

    private RSAKey generateEphemeralKey() {
        try {
            KeyPairGenerator generator = KeyPairGenerator.getInstance("RSA");
            generator.initialize(2048);
            KeyPair pair = generator.generateKeyPair();
            return new RSAKey.Builder((RSAPublicKey) pair.getPublic())
                    .privateKey(pair.getPrivate())
                    .keyID("ephemeral-" + System.currentTimeMillis())
                    .keyUse(KeyUse.SIGNATURE)
                    .algorithm(JWSAlgorithm.RS256)
                    .build();
        } catch (Exception e) {
            throw new IllegalStateException("Could not generate an ephemeral signing key", e);
        }
    }

    private record KeyDefinition(String kid, boolean active, String privateKey, String publicKey) {
    }

    public boolean canSign() {
        try {
            return activeKey.toRSAPrivateKey() != null;
        } catch (JOSEException e) {
            return false;
        }
    }
}
