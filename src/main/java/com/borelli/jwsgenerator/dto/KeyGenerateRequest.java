package com.borelli.jwsgenerator.dto;

import jakarta.validation.constraints.NotNull;
import jakarta.validation.constraints.Pattern;
import jakarta.validation.constraints.Positive;

/**
 * Request payload for generating a cryptographic key pair.
 *
 * <p>For RSA, valid sizes are {@code 2048} and {@code 4096}.
 * For EC, valid curve sizes are {@code 256}, {@code 384}, and {@code 521}.
 * If {@code keySize} is omitted, a secure default is used ({@code 2048} for RSA, {@code 256} for EC).
 */
public record KeyGenerateRequest(

        @NotNull(message = "algorithm is required")
        @Pattern(
                regexp = "RSA|EC",
                message = "algorithm must be one of: RSA, EC"
        )
        String algorithm,

        @Positive(message = "keySize must be a positive integer")
        Integer keySize
) {}
