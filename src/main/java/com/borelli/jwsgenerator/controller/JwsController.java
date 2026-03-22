package com.borelli.jwsgenerator.controller;

import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import com.borelli.jwsgenerator.dto.JwsRequest;
import com.borelli.jwsgenerator.dto.JwsResponse;
import com.borelli.jwsgenerator.dto.JwsVerifyRequest;
import com.borelli.jwsgenerator.dto.JwsVerifyResponse;
import com.borelli.jwsgenerator.dto.KeyGenerateRequest;
import com.borelli.jwsgenerator.dto.KeyGenerateResponse;
import com.borelli.jwsgenerator.service.JwsService;

import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.media.Content;
import io.swagger.v3.oas.annotations.media.Schema;
import io.swagger.v3.oas.annotations.responses.ApiResponse;
import io.swagger.v3.oas.annotations.responses.ApiResponses;
import io.swagger.v3.oas.annotations.tags.Tag;
import jakarta.validation.Valid;

/**
 * REST controller that exposes endpoints for JWS generation, verification, and key-pair generation.
 *
 * <p>Base path: {@code /api/v1}
 */
@RestController
@RequestMapping("/api/v1")
@Tag(name = "JWS Operations", description = "Endpoints for JSON Web Signature generation, verification, and key management")
public class JwsController {

    private final JwsService jwsService;

    public JwsController(JwsService jwsService) {
        this.jwsService = jwsService;
    }

    /**
     * Generates a compact JWS from the provided payload and signing key.
     *
     * <p><strong>POST /api/v1/jws/generate</strong>
     *
     * @param request the JWS generation request
     * @return {@code 201 Created} with the generated {@link JwsResponse}
     */
    @Operation(summary = "Generate JWS", description = "Generates a compact JSON Web Signature from payload and private key")
    @ApiResponses(value = {
        @ApiResponse(responseCode = "201", description = "JWS successfully generated",
                content = @Content(schema = @Schema(implementation = JwsResponse.class))),
        @ApiResponse(responseCode = "400", description = "Invalid request parameters"),
        @ApiResponse(responseCode = "500", description = "Internal server error during JWS generation")
    })
    @PostMapping("/jws/generate")
    public ResponseEntity<JwsResponse> generate(@Valid @RequestBody JwsRequest request) {
        JwsResponse response = jwsService.generate(request);
        return ResponseEntity.status(HttpStatus.CREATED).body(response);
    }

    /**
     * Verifies a compact JWS and returns the decoded payload when valid.
     *
     * <p><strong>POST /api/v1/jws/verify</strong>
     *
     * @param request the JWS verification request
     * @return {@code 200 OK} with the {@link JwsVerifyResponse}
     */
    @Operation(summary = "Verify JWS", description = "Verifies a compact JWS signature and returns the decoded payload")
    @ApiResponses(value = {
        @ApiResponse(responseCode = "200", description = "JWS successfully verified",
                content = @Content(schema = @Schema(implementation = JwsVerifyResponse.class))),
        @ApiResponse(responseCode = "400", description = "Invalid request or signature verification failed"),
        @ApiResponse(responseCode = "500", description = "Internal server error during JWS verification")
    })
    @PostMapping("/jws/verify")
    public ResponseEntity<JwsVerifyResponse> verify(@Valid @RequestBody JwsVerifyRequest request) {
        JwsVerifyResponse response = jwsService.verify(request);
        return ResponseEntity.ok(response);
    }

    /**
     * Generates an RSA or EC key pair and returns PEM-encoded keys.
     *
     * <p><strong>POST /api/v1/keys/generate</strong>
     *
     * @param request the key-generation request
     * @return {@code 201 Created} with the {@link KeyGenerateResponse}
     */
    @Operation(summary = "Generate Key Pair", description = "Generates an RSA or EC key pair for JWS signing")
    @ApiResponses(value = {
        @ApiResponse(responseCode = "201", description = "Key pair successfully generated",
                content = @Content(schema = @Schema(implementation = KeyGenerateResponse.class))),
        @ApiResponse(responseCode = "400", description = "Invalid key generation parameters"),
        @ApiResponse(responseCode = "500", description = "Internal server error during key generation")
    })
    @PostMapping("/keys/generate")
    public ResponseEntity<KeyGenerateResponse> generateKeyPair(@Valid @RequestBody KeyGenerateRequest request) {
        KeyGenerateResponse response = jwsService.generateKeyPair(request);
        return ResponseEntity.status(HttpStatus.CREATED).body(response);
    }
}
