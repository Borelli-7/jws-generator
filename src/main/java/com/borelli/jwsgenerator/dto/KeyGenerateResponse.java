package com.borelli.jwsgenerator.dto;

import io.swagger.v3.oas.annotations.media.Schema;

/**
 * Response returned after generating a cryptographic key pair.
 *
 * <p>Both keys are PEM-encoded:
 * <ul>
 *   <li>{@code privateKey} – PKCS#8 private key (for use in {@link JwsRequest#privateKey()})</li>
 *   <li>{@code publicKey}  – X.509 SubjectPublicKeyInfo public key (for use in {@link JwsVerifyRequest#publicKey()})</li>
 * </ul>
 *
 * @param algorithm  The algorithm type ({@code RSA} or {@code EC})
 * @param keySize    The effective key size in bits
 * @param privateKey PEM-encoded PKCS#8 private key
 * @param publicKey  PEM-encoded X.509 public key
 */
@Schema(description = "Response containing the generated key pair")
public record KeyGenerateResponse(
        @Schema(description = "Algorithm type", example = "RSA")
        String algorithm,
        
        @Schema(description = "Key size in bits", example = "2048")
        int keySize,
        
        @Schema(description = "PEM-encoded PKCS#8 private key")
        String privateKey,
        
        @Schema(description = "PEM-encoded X.509 public key")
        String publicKey
) {}
