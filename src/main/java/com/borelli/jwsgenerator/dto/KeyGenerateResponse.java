package com.borelli.jwsgenerator.dto;

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
public record KeyGenerateResponse(
        String algorithm,
        int keySize,
        String privateKey,
        String publicKey
) {}
