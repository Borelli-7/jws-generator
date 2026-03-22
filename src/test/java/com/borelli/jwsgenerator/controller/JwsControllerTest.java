package com.borelli.jwsgenerator.controller;

import com.borelli.jwsgenerator.dto.*;
import com.borelli.jwsgenerator.service.JwsService;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.WebMvcTest;
import org.springframework.boot.test.mock.mockito.MockBean;
import org.springframework.http.MediaType;
import org.springframework.test.web.servlet.MockMvc;

import java.util.Map;

import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.when;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.*;

@WebMvcTest(JwsController.class)
class JwsControllerTest {

    @Autowired
    private MockMvc mockMvc;

    @Autowired
    private ObjectMapper objectMapper;

    @MockBean
    private JwsService jwsService;

    private static final String GENERATE_URL    = "/api/v1/jws/generate";
    private static final String VERIFY_URL      = "/api/v1/jws/verify";
    private static final String KEY_GEN_URL     = "/api/v1/keys/generate";

    // -----------------------------------------------------------------------
    // /jws/generate
    // -----------------------------------------------------------------------

    @Test
    @DisplayName("POST /jws/generate – returns 201 with JwsResponse")
    void generateReturns201() throws Exception {
        JwsRequest request = new JwsRequest("HS256", "{\"sub\":\"1\"}", "secret-key-long-enough", null, null);
        JwsResponse mockResponse = new JwsResponse("a.b.c", "HS256", "{\"alg\":\"HS256\"}", "{\"sub\":\"1\"}");

        when(jwsService.generate(any())).thenReturn(mockResponse);

        mockMvc.perform(post(GENERATE_URL)
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(request)))
                .andExpect(status().isCreated())
                .andExpect(jsonPath("$.jws").value("a.b.c"))
                .andExpect(jsonPath("$.algorithm").value("HS256"));
    }

    @Test
    @DisplayName("POST /jws/generate – returns 400 when algorithm is missing")
    void generateReturns400WhenAlgorithmMissing() throws Exception {
        Map<String, Object> body = Map.of("payload", "hello");

        mockMvc.perform(post(GENERATE_URL)
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(body)))
                .andExpect(status().isBadRequest());
    }

    @Test
    @DisplayName("POST /jws/generate – returns 400 when algorithm is invalid")
    void generateReturns400WhenAlgorithmInvalid() throws Exception {
        JwsRequest request = new JwsRequest("INVALID", "payload", "secret", null, null);

        mockMvc.perform(post(GENERATE_URL)
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(request)))
                .andExpect(status().isBadRequest());
    }

    @Test
    @DisplayName("POST /jws/generate – returns 400 when payload is blank")
    void generateReturns400WhenPayloadBlank() throws Exception {
        JwsRequest request = new JwsRequest("HS256", "", "secret", null, null);

        mockMvc.perform(post(GENERATE_URL)
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(request)))
                .andExpect(status().isBadRequest());
    }

    // -----------------------------------------------------------------------
    // /jws/verify
    // -----------------------------------------------------------------------

    @Test
    @DisplayName("POST /jws/verify – returns 200 with JwsVerifyResponse")
    void verifyReturns200() throws Exception {
        JwsVerifyRequest request = new JwsVerifyRequest("a.b.c", "secret", null);
        JwsVerifyResponse mockResponse = new JwsVerifyResponse(true, "{\"alg\":\"HS256\"}", "payload", "Signature is valid");

        when(jwsService.verify(any())).thenReturn(mockResponse);

        mockMvc.perform(post(VERIFY_URL)
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(request)))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.valid").value(true))
                .andExpect(jsonPath("$.message").value("Signature is valid"));
    }

    @Test
    @DisplayName("POST /jws/verify – returns 400 when jws field is missing")
    void verifyReturns400WhenJwsMissing() throws Exception {
        Map<String, Object> body = Map.of("secret", "key");

        mockMvc.perform(post(VERIFY_URL)
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(body)))
                .andExpect(status().isBadRequest());
    }

    // -----------------------------------------------------------------------
    // /keys/generate
    // -----------------------------------------------------------------------

    @Test
    @DisplayName("POST /keys/generate – returns 201 with KeyGenerateResponse")
    void keyGenerateReturns201() throws Exception {
        KeyGenerateRequest request = new KeyGenerateRequest("RSA", 2048);
        KeyGenerateResponse mockResponse = new KeyGenerateResponse("RSA", 2048,
                "-----BEGIN PRIVATE KEY-----\nMIIE...\n-----END PRIVATE KEY-----\n",
                "-----BEGIN PUBLIC KEY-----\nMIIB...\n-----END PUBLIC KEY-----\n");

        when(jwsService.generateKeyPair(any())).thenReturn(mockResponse);

        mockMvc.perform(post(KEY_GEN_URL)
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(request)))
                .andExpect(status().isCreated())
                .andExpect(jsonPath("$.algorithm").value("RSA"))
                .andExpect(jsonPath("$.keySize").value(2048));
    }

    @Test
    @DisplayName("POST /keys/generate – returns 400 when algorithm is invalid")
    void keyGenerateReturns400WhenAlgorithmInvalid() throws Exception {
        KeyGenerateRequest request = new KeyGenerateRequest("DSA", 2048);

        mockMvc.perform(post(KEY_GEN_URL)
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(request)))
                .andExpect(status().isBadRequest());
    }
}
