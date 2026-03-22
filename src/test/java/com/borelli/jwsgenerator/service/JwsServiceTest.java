package com.borelli.jwsgenerator.service;

import com.borelli.jwsgenerator.dto.*;
import com.borelli.jwsgenerator.exception.JwsOperationException;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;

import java.util.Map;

import static org.assertj.core.api.Assertions.*;

class JwsServiceTest {

    private JwsService jwsService;

    @BeforeEach
    void setUp() {
        jwsService = new JwsService();
    }

    // -----------------------------------------------------------------------
    // HMAC tests
    // -----------------------------------------------------------------------

    @Nested
    @DisplayName("HMAC (HS256 / HS384 / HS512)")
    class HmacTests {

        // A 64-byte secret satisfies the minimum key length for HS256, HS384, and HS512
        private static final String SECRET = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
        private static final String PAYLOAD = "{\"sub\":\"1234\",\"name\":\"Alice\"}";

        @Test
        @DisplayName("HS256 – generate and verify round-trip")
        void hs256RoundTrip() {
            JwsRequest req = new JwsRequest("HS256", PAYLOAD, SECRET, null, null);
            JwsResponse response = jwsService.generate(req);

            assertThat(response.jws()).isNotBlank();
            assertThat(response.algorithm()).isEqualTo("HS256");
            assertThat(response.payload()).isEqualTo(PAYLOAD);
            assertThat(response.header()).contains("HS256");

            JwsVerifyRequest verifyReq = new JwsVerifyRequest(response.jws(), SECRET, null);
            JwsVerifyResponse verifyResp = jwsService.verify(verifyReq);

            assertThat(verifyResp.valid()).isTrue();
            assertThat(verifyResp.payload()).isEqualTo(PAYLOAD);
        }

        @Test
        @DisplayName("HS384 – generate and verify round-trip")
        void hs384RoundTrip() {
            JwsRequest req = new JwsRequest("HS384", PAYLOAD, SECRET, null, null);
            JwsResponse response = jwsService.generate(req);
            assertThat(response.algorithm()).isEqualTo("HS384");

            JwsVerifyRequest verifyReq = new JwsVerifyRequest(response.jws(), SECRET, null);
            assertThat(jwsService.verify(verifyReq).valid()).isTrue();
        }

        @Test
        @DisplayName("HS512 – generate and verify round-trip")
        void hs512RoundTrip() {
            JwsRequest req = new JwsRequest("HS512", PAYLOAD, SECRET, null, null);
            JwsResponse response = jwsService.generate(req);
            assertThat(response.algorithm()).isEqualTo("HS512");

            JwsVerifyRequest verifyReq = new JwsVerifyRequest(response.jws(), SECRET, null);
            assertThat(jwsService.verify(verifyReq).valid()).isTrue();
        }

        @Test
        @DisplayName("Verification fails with wrong secret")
        void wrongSecretFails() {
            JwsRequest req = new JwsRequest("HS256", PAYLOAD, SECRET, null, null);
            JwsResponse response = jwsService.generate(req);

            JwsVerifyRequest verifyReq = new JwsVerifyRequest(response.jws(), "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef-WRONG", null);
            JwsVerifyResponse verifyResp = jwsService.verify(verifyReq);

            assertThat(verifyResp.valid()).isFalse();
        }

        @Test
        @DisplayName("Missing secret throws JwsOperationException")
        void missingSecretThrows() {
            JwsRequest req = new JwsRequest("HS256", PAYLOAD, null, null, null);
            assertThatThrownBy(() -> jwsService.generate(req))
                    .isInstanceOf(JwsOperationException.class)
                    .hasMessageContaining("secret");
        }

        @Test
        @DisplayName("Custom headers are included in the JWS header")
        void customHeadersAreIncluded() {
            JwsRequest req = new JwsRequest("HS256", PAYLOAD, SECRET, null, Map.of("kid", "key-1"));
            JwsResponse response = jwsService.generate(req);
            assertThat(response.header()).contains("key-1");
        }
    }

    // -----------------------------------------------------------------------
    // RSA tests
    // -----------------------------------------------------------------------

    @Nested
    @DisplayName("RSA (RS256 / RS384 / RS512)")
    class RsaTests {

        private String privateKeyPem;
        private String publicKeyPem;

        @BeforeEach
        void generateKeys() {
            KeyGenerateResponse keys = jwsService.generateKeyPair(new KeyGenerateRequest("RSA", 2048));
            privateKeyPem = keys.privateKey();
            publicKeyPem  = keys.publicKey();
        }

        @Test
        @DisplayName("RS256 – generate and verify round-trip")
        void rs256RoundTrip() {
            String payload = "{\"iss\":\"test\",\"sub\":\"user-1\"}";
            JwsRequest req = new JwsRequest("RS256", payload, null, privateKeyPem, null);
            JwsResponse response = jwsService.generate(req);

            assertThat(response.jws()).isNotBlank();
            assertThat(response.algorithm()).isEqualTo("RS256");

            JwsVerifyRequest verifyReq = new JwsVerifyRequest(response.jws(), null, publicKeyPem);
            JwsVerifyResponse verifyResp = jwsService.verify(verifyReq);

            assertThat(verifyResp.valid()).isTrue();
            assertThat(verifyResp.payload()).isEqualTo(payload);
        }

        @Test
        @DisplayName("RS512 – generate and verify round-trip")
        void rs512RoundTrip() {
            String payload = "{\"sub\":\"user-2\"}";
            JwsRequest req = new JwsRequest("RS512", payload, null, privateKeyPem, null);
            JwsResponse response = jwsService.generate(req);

            JwsVerifyRequest verifyReq = new JwsVerifyRequest(response.jws(), null, publicKeyPem);
            assertThat(jwsService.verify(verifyReq).valid()).isTrue();
        }

        @Test
        @DisplayName("Missing privateKey throws JwsOperationException")
        void missingPrivateKeyThrows() {
            JwsRequest req = new JwsRequest("RS256", "payload", null, null, null);
            assertThatThrownBy(() -> jwsService.generate(req))
                    .isInstanceOf(JwsOperationException.class)
                    .hasMessageContaining("privateKey");
        }
    }

    // -----------------------------------------------------------------------
    // EC tests
    // -----------------------------------------------------------------------

    @Nested
    @DisplayName("ECDSA (ES256 / ES384 / ES512)")
    class EcTests {

        @Test
        @DisplayName("ES256 (P-256) – generate and verify round-trip")
        void es256RoundTrip() {
            KeyGenerateResponse keys = jwsService.generateKeyPair(new KeyGenerateRequest("EC", 256));
            String payload = "{\"sub\":\"ec-user\"}";
            JwsRequest req = new JwsRequest("ES256", payload, null, keys.privateKey(), null);
            JwsResponse response = jwsService.generate(req);

            assertThat(response.algorithm()).isEqualTo("ES256");

            JwsVerifyRequest verifyReq = new JwsVerifyRequest(response.jws(), null, keys.publicKey());
            assertThat(jwsService.verify(verifyReq).valid()).isTrue();
        }

        @Test
        @DisplayName("ES384 (P-384) – generate and verify round-trip")
        void es384RoundTrip() {
            KeyGenerateResponse keys = jwsService.generateKeyPair(new KeyGenerateRequest("EC", 384));
            String payload = "{\"sub\":\"ec-user-384\"}";
            JwsRequest req = new JwsRequest("ES384", payload, null, keys.privateKey(), null);
            JwsResponse response = jwsService.generate(req);

            JwsVerifyRequest verifyReq = new JwsVerifyRequest(response.jws(), null, keys.publicKey());
            assertThat(jwsService.verify(verifyReq).valid()).isTrue();
        }

        @Test
        @DisplayName("ES512 (P-521) – generate and verify round-trip")
        void es512RoundTrip() {
            KeyGenerateResponse keys = jwsService.generateKeyPair(new KeyGenerateRequest("EC", 521));
            String payload = "{\"sub\":\"ec-user-521\"}";
            JwsRequest req = new JwsRequest("ES512", payload, null, keys.privateKey(), null);
            JwsResponse response = jwsService.generate(req);

            JwsVerifyRequest verifyReq = new JwsVerifyRequest(response.jws(), null, keys.publicKey());
            assertThat(jwsService.verify(verifyReq).valid()).isTrue();
        }
    }

    // -----------------------------------------------------------------------
    // Key generation tests
    // -----------------------------------------------------------------------

    @Nested
    @DisplayName("Key pair generation")
    class KeyGenerationTests {

        @Test
        @DisplayName("RSA 2048 key pair is generated with PEM output")
        void rsa2048() {
            KeyGenerateResponse resp = jwsService.generateKeyPair(new KeyGenerateRequest("RSA", 2048));
            assertThat(resp.algorithm()).isEqualTo("RSA");
            assertThat(resp.keySize()).isEqualTo(2048);
            assertThat(resp.privateKey()).contains("BEGIN PRIVATE KEY");
            assertThat(resp.publicKey()).contains("BEGIN PUBLIC KEY");
        }

        @Test
        @DisplayName("RSA 4096 key pair is generated with PEM output")
        void rsa4096() {
            KeyGenerateResponse resp = jwsService.generateKeyPair(new KeyGenerateRequest("RSA", 4096));
            assertThat(resp.keySize()).isEqualTo(4096);
        }

        @Test
        @DisplayName("EC P-256 key pair is generated with PEM output")
        void ecP256() {
            KeyGenerateResponse resp = jwsService.generateKeyPair(new KeyGenerateRequest("EC", 256));
            assertThat(resp.algorithm()).isEqualTo("EC");
            assertThat(resp.keySize()).isEqualTo(256);
            assertThat(resp.privateKey()).contains("BEGIN PRIVATE KEY");
            assertThat(resp.publicKey()).contains("BEGIN PUBLIC KEY");
        }

        @Test
        @DisplayName("Invalid RSA key size throws IllegalArgumentException")
        void invalidRsaKeySize() {
            assertThatThrownBy(() -> jwsService.generateKeyPair(new KeyGenerateRequest("RSA", 1024)))
                    .isInstanceOf(IllegalArgumentException.class)
                    .hasMessageContaining("2048 or 4096");
        }

        @Test
        @DisplayName("Invalid EC curve size throws IllegalArgumentException")
        void invalidEcCurveSize() {
            assertThatThrownBy(() -> jwsService.generateKeyPair(new KeyGenerateRequest("EC", 128)))
                    .isInstanceOf(IllegalArgumentException.class)
                    .hasMessageContaining("256, 384, or 521");
        }

        @Test
        @DisplayName("Default RSA key size (null) uses 2048")
        void defaultRsaKeySize() {
            KeyGenerateResponse resp = jwsService.generateKeyPair(new KeyGenerateRequest("RSA", null));
            assertThat(resp.keySize()).isEqualTo(2048);
        }

        @Test
        @DisplayName("Default EC key size (null) uses 256")
        void defaultEcKeySize() {
            KeyGenerateResponse resp = jwsService.generateKeyPair(new KeyGenerateRequest("EC", null));
            assertThat(resp.keySize()).isEqualTo(256);
        }
    }

    // -----------------------------------------------------------------------
    // Verify edge cases
    // -----------------------------------------------------------------------

    @Nested
    @DisplayName("Verify edge cases")
    class VerifyEdgeCases {

        @Test
        @DisplayName("Malformed JWS string returns invalid response")
        void malformedJws() {
            JwsVerifyRequest req = new JwsVerifyRequest("not.a.valid.jws.token", "secret", null);
            JwsVerifyResponse resp = jwsService.verify(req);
            assertThat(resp.valid()).isFalse();
            assertThat(resp.message()).contains("Malformed");
        }
    }
}
