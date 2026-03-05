package com.borelli.jwsgenerator.dto;

import jakarta.validation.constraints.NotBlank;

/**
 * Request payload for verifying a JSON Web Signature.
 *
 * <p>Provide {@code secret} for HMAC algorithms, or {@code publicKey} for RSA/EC algorithms.
 */
public record JwsVerifyRequest(

        @NotBlank(message = "jws is required")
        String jws,

        String secret,

        String publicKey
) {}
