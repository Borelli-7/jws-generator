package com.borelli.jwsgenerator.dto;

import java.util.Map;

import io.swagger.v3.oas.annotations.media.Schema;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.NotNull;
import jakarta.validation.constraints.Pattern;

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
@Schema(description = "Request for generating a JSON Web Signature")
public record JwsRequest(

        @Schema(description = "Algorithm to use for signing", example = "RS256", 
                allowableValues = {"HS256", "HS384", "HS512", "RS256", "RS384", "RS512", "ES256", "ES384", "ES512"})
        @NotNull(message = "algorithm is required")
        @Pattern(
                regexp = "HS256|HS384|HS512|RS256|RS384|RS512|ES256|ES384|ES512",
                message = "algorithm must be one of: HS256, HS384, HS512, RS256, RS384, RS512, ES256, ES384, ES512"
        )
        String algorithm,

        @Schema(description = "Payload data to sign", example = "{\"sub\":\"1234567890\",\"name\":\"John Doe\"}")
        @NotBlank(message = "payload is required")
        String payload,

        @Schema(description = "Secret key for HMAC algorithms (HS256, HS384, HS512)", example = "my-secret-key", nullable = true)
        String secret,

        @Schema(description = "PEM-encoded private key for RSA/EC algorithms", nullable = true)
        String privateKey,

        @Schema(description = "Additional headers to include in the JWS", nullable = true)
        Map<String, Object> headers
) {}
