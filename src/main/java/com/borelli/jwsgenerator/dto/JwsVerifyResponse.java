package com.borelli.jwsgenerator.dto;

import io.swagger.v3.oas.annotations.media.Schema;

/**
 * Response returned after verifying a JSON Web Signature.
 *
 * @param valid   Whether the signature is valid
 * @param header  The decoded JWS protected header (JSON string), present only when {@code valid} is {@code true}
 * @param payload The decoded JWS payload, present only when {@code valid} is {@code true}
 * @param message A human-readable status or error message
 */
@Schema(description = "Response from JWS verification")
public record JwsVerifyResponse(
        @Schema(description = "Whether the signature is valid", example = "true")
        boolean valid,
        
        @Schema(description = "Decoded JWS header (present when valid)", nullable = true)
        String header,
        
        @Schema(description = "Decoded payload (present when valid)", nullable = true)
        String payload,
        
        @Schema(description = "Status or error message", example = "Signature is valid")
        String message
) {}
