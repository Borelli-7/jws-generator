package com.borelli.jwsgenerator.dto;

import io.swagger.v3.oas.annotations.media.Schema;
import jakarta.validation.constraints.NotBlank;

/**
 * Request payload for verifying a JSON Web Signature.
 *
 * <p>Provide {@code secret} for HMAC algorithms, or {@code publicKey} for RSA/EC algorithms.
 */
@Schema(description = "Request for verifying a JSON Web Signature")
public record JwsVerifyRequest(

        @Schema(description = "Compact JWS to verify", 
                example = "eyJhbGciOiJSUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIn0.signature")
        @NotBlank(message = "jws is required")
        String jws,

        @Schema(description = "Secret key for HMAC algorithms", nullable = true)
        String secret,

        @Schema(description = "PEM-encoded public key for RSA/EC algorithms", nullable = true)
        String publicKey
) {}
