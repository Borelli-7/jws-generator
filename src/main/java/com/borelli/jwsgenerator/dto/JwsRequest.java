package com.borelli.jwsgenerator.dto;

import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.NotNull;
import jakarta.validation.constraints.Pattern;

import java.util.Map;

/**
 * Request payload for generating a JSON Web Signature.
 *
 * <p>Supported algorithms:
 * <ul>
 *   <li>HMAC: {@code HS256}, {@code HS384}, {@code HS512} – requires {@code secret}</li>
 *   <li>RSA:  {@code RS256}, {@code RS384}, {@code RS512} – requires {@code privateKey}</li>
 *   <li>ECDSA: {@code ES256}, {@code ES384}, {@code ES512} – requires {@code privateKey}</li>
 * </ul>
 */
public record JwsRequest(

        @NotNull(message = "algorithm is required")
        @Pattern(
                regexp = "HS256|HS384|HS512|RS256|RS384|RS512|ES256|ES384|ES512",
                message = "algorithm must be one of: HS256, HS384, HS512, RS256, RS384, RS512, ES256, ES384, ES512"
        )
        String algorithm,

        @NotBlank(message = "payload is required")
        String payload,

        String secret,

        String privateKey,

        Map<String, Object> headers
) {}
