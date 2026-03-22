package com.borelli.jwsgenerator.dto;

import io.swagger.v3.oas.annotations.media.Schema;

/**
 * Response returned after successfully generating a JSON Web Signature.
 *
 * @param jws       The compact JWS serialization: {@code header.payload.signature}
 * @param algorithm The algorithm used to sign the JWS
 * @param header    The decoded JWS protected header (JSON string)
 * @param payload   The decoded JWS payload string
 */
@Schema(description = "Response containing the generated JWS")
public record JwsResponse(
        @Schema(description = "Compact JWS serialization (header.payload.signature)", 
                example = "eyJhbGciOiJSUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIn0.signature")
        String jws,
        
        @Schema(description = "Algorithm used for signing", example = "RS256")
        String algorithm,
        
        @Schema(description = "Decoded JWS header as JSON", example = "{\"alg\":\"RS256\",\"typ\":\"JOSE\"}")
        String header,
        
        @Schema(description = "Decoded payload", example = "{\"sub\":\"1234567890\",\"name\":\"John Doe\"}")
        String payload
) {}
