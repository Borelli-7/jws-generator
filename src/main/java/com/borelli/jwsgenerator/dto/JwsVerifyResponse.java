package com.borelli.jwsgenerator.dto;

/**
 * Response returned after verifying a JSON Web Signature.
 *
 * @param valid   Whether the signature is valid
 * @param header  The decoded JWS protected header (JSON string), present only when {@code valid} is {@code true}
 * @param payload The decoded JWS payload, present only when {@code valid} is {@code true}
 * @param message A human-readable status or error message
 */
public record JwsVerifyResponse(
        boolean valid,
        String header,
        String payload,
        String message
) {}
