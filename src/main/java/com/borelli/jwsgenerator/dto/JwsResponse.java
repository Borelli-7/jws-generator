package com.borelli.jwsgenerator.dto;

/**
 * Response returned after successfully generating a JSON Web Signature.
 *
 * @param jws       The compact JWS serialization: {@code header.payload.signature}
 * @param algorithm The algorithm used to sign the JWS
 * @param header    The decoded JWS protected header (JSON string)
 * @param payload   The decoded JWS payload string
 */
public record JwsResponse(
        String jws,
        String algorithm,
        String header,
        String payload
) {}
