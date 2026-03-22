package com.borelli.jwsgenerator.controller;

import com.borelli.jwsgenerator.dto.*;
import com.borelli.jwsgenerator.service.JwsService;
import jakarta.validation.Valid;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

/**
 * REST controller that exposes endpoints for JWS generation, verification, and key-pair generation.
 *
 * <p>Base path: {@code /api/v1}
 */
@RestController
@RequestMapping("/api/v1")
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
    @PostMapping("/keys/generate")
    public ResponseEntity<KeyGenerateResponse> generateKeyPair(@Valid @RequestBody KeyGenerateRequest request) {
        KeyGenerateResponse response = jwsService.generateKeyPair(request);
        return ResponseEntity.status(HttpStatus.CREATED).body(response);
    }
}
