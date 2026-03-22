package com.borelli.jwsgenerator.service;

import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.security.KeyFactory;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.interfaces.ECPrivateKey;
import java.security.interfaces.ECPublicKey;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;
import java.util.Map;
import java.util.UUID;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Service;

import com.borelli.jwsgenerator.dto.JwsRequest;
import com.borelli.jwsgenerator.dto.JwsResponse;
import com.borelli.jwsgenerator.dto.JwsVerifyRequest;
import com.borelli.jwsgenerator.dto.JwsVerifyResponse;
import com.borelli.jwsgenerator.dto.KeyGenerateRequest;
import com.borelli.jwsgenerator.dto.KeyGenerateResponse;
import com.borelli.jwsgenerator.exception.JwsOperationException;
import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JOSEObjectType;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.JWSObject;
import com.nimbusds.jose.JWSSigner;
import com.nimbusds.jose.JWSVerifier;
import com.nimbusds.jose.Payload;
import com.nimbusds.jose.crypto.ECDSASigner;
import com.nimbusds.jose.crypto.ECDSAVerifier;
import com.nimbusds.jose.crypto.MACSigner;
import com.nimbusds.jose.crypto.MACVerifier;
import com.nimbusds.jose.crypto.RSASSASigner;
import com.nimbusds.jose.crypto.RSASSAVerifier;
import com.nimbusds.jose.jwk.Curve;
import com.nimbusds.jose.jwk.ECKey;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jose.jwk.gen.ECKeyGenerator;
import com.nimbusds.jose.jwk.gen.RSAKeyGenerator;

/**
 * Service responsible for JWS generation, verification, and key-pair generation.
 *
 * <p>Supported algorithms:
 * <ul>
 *   <li>HMAC  – HS256, HS384, HS512</li>
 *   <li>RSA   – RS256, RS384, RS512</li>
 *   <li>ECDSA – ES256, ES384, ES512</li>
 * </ul>
 */
@Service
public class JwsService {

    private static final Logger log = LoggerFactory.getLogger(JwsService.class);

    // -----------------------------------------------------------------------
    // JWS generation
    // -----------------------------------------------------------------------

    /**
     * Generates a compact JWS serialization from the provided request.
     */
    public JwsResponse generate(JwsRequest request) {
        JWSAlgorithm algorithm = resolveAlgorithm(request.algorithm());
        JWSHeader header = buildHeader(algorithm, request.headers());

        JWSObject jwsObject = new JWSObject(header, new Payload(request.payload()));

        try {
            JWSSigner signer = createSigner(request);
            jwsObject.sign(signer);
        } catch (JOSEException e) {
            throw new JwsOperationException("Failed to sign JWS: " + e.getMessage(), e);
        }

        String compactJws = jwsObject.serialize();
        log.debug("Generated JWS with algorithm {}", algorithm.getName());

        return new JwsResponse(
                compactJws,
                algorithm.getName(),
                jwsObject.getHeader().toJSONObject().toString(),
                request.payload()
        );
    }

    // -----------------------------------------------------------------------
    // JWS verification
    // -----------------------------------------------------------------------

    /**
     * Verifies a compact JWS serialization and returns the decoded payload when valid.
     */
    public JwsVerifyResponse verify(JwsVerifyRequest request) {
        JWSObject jwsObject;
        try {
            jwsObject = JWSObject.parse(request.jws());
        } catch (java.text.ParseException e) {
            return new JwsVerifyResponse(false, null, null, "Malformed JWS: " + e.getMessage());
        }

        JWSAlgorithm algorithm = jwsObject.getHeader().getAlgorithm();
        boolean valid;

        try {
            JWSVerifier verifier = createVerifier(request, algorithm);
            valid = jwsObject.verify(verifier);
        } catch (JOSEException | JwsOperationException e) {
            return new JwsVerifyResponse(false, null, null, "Verification error: " + e.getMessage());
        }

        if (valid) {
            return new JwsVerifyResponse(
                    true,
                    jwsObject.getHeader().toJSONObject().toString(),
                    jwsObject.getPayload().toString(),
                    "Signature is valid"
            );
        }
        return new JwsVerifyResponse(false, null, null, "Signature is invalid");
    }

    // -----------------------------------------------------------------------
    // Key-pair generation
    // -----------------------------------------------------------------------

    /**
     * Generates an RSA or EC key pair, returning PEM-encoded keys.
     */
    public KeyGenerateResponse generateKeyPair(KeyGenerateRequest request) {
        return switch (request.algorithm()) {
            case "RSA" -> generateRsaKeyPair(request.keySize());
            case "EC"  -> generateEcKeyPair(request.keySize());
            default    -> throw new IllegalArgumentException("Unsupported algorithm: " + request.algorithm());
        };
    }

    // -----------------------------------------------------------------------
    // Private helpers – algorithm resolution
    // -----------------------------------------------------------------------

    private JWSAlgorithm resolveAlgorithm(String name) {
        return switch (name) {
            case "HS256" -> JWSAlgorithm.HS256;
            case "HS384" -> JWSAlgorithm.HS384;
            case "HS512" -> JWSAlgorithm.HS512;
            case "RS256" -> JWSAlgorithm.RS256;
            case "RS384" -> JWSAlgorithm.RS384;
            case "RS512" -> JWSAlgorithm.RS512;
            case "ES256" -> JWSAlgorithm.ES256;
            case "ES384" -> JWSAlgorithm.ES384;
            case "ES512" -> JWSAlgorithm.ES512;
            default      -> throw new IllegalArgumentException("Unsupported algorithm: " + name);
        };
    }

    private JWSHeader buildHeader(JWSAlgorithm algorithm, Map<String, Object> extraHeaders) {
        JWSHeader.Builder builder = new JWSHeader.Builder(algorithm)
                .type(JOSEObjectType.JOSE);

        if (extraHeaders != null) {
            extraHeaders.forEach((key, value) -> {
                if ("kid".equals(key) && value instanceof String kid) {
                    builder.keyID(kid);
                } else {
                    builder.customParam(key, value);
                }
            });
        }

        return builder.build();
    }

    // -----------------------------------------------------------------------
    // Private helpers – signer construction
    // -----------------------------------------------------------------------

    private JWSSigner createSigner(JwsRequest request) throws JOSEException {
        String alg = request.algorithm();
        if (alg.startsWith("HS")) {
            return buildHmacSigner(request);
        } else if (alg.startsWith("RS")) {
            return buildRsaSigner(request);
        } else if (alg.startsWith("ES")) {
            return buildEcSigner(request);
        }
        throw new IllegalArgumentException("Unsupported algorithm: " + alg);
    }

    private MACSigner buildHmacSigner(JwsRequest request) throws JOSEException {
        if (request.secret() == null || request.secret().isBlank()) {
            throw new JwsOperationException("'secret' is required for HMAC algorithms");
        }
        byte[] keyBytes = request.secret().getBytes(StandardCharsets.UTF_8);
        return new MACSigner(keyBytes);
    }

    private RSASSASigner buildRsaSigner(JwsRequest request) {
        if (request.privateKey() == null || request.privateKey().isBlank()) {
            throw new JwsOperationException("'privateKey' is required for RSA algorithms");
        }
        RSAPrivateKey privateKey = (RSAPrivateKey) parsePkcs8PrivateKey(request.privateKey(), "RSA");
        return new RSASSASigner(privateKey);
    }

    private ECDSASigner buildEcSigner(JwsRequest request) throws JOSEException {
        if (request.privateKey() == null || request.privateKey().isBlank()) {
            throw new JwsOperationException("'privateKey' is required for EC algorithms");
        }
        ECPrivateKey privateKey = (ECPrivateKey) parsePkcs8PrivateKey(request.privateKey(), "EC");
        return new ECDSASigner(privateKey);
    }

    // -----------------------------------------------------------------------
    // Private helpers – verifier construction
    // -----------------------------------------------------------------------

    private JWSVerifier createVerifier(JwsVerifyRequest request, JWSAlgorithm algorithm) throws JOSEException {
        String algName = algorithm.getName();
        if (algName.startsWith("HS")) {
            return buildHmacVerifier(request);
        } else if (algName.startsWith("RS")) {
            return buildRsaVerifier(request);
        } else if (algName.startsWith("ES")) {
            return buildEcVerifier(request);
        }
        throw new JwsOperationException("Unsupported algorithm for verification: " + algName);
    }

    private MACVerifier buildHmacVerifier(JwsVerifyRequest request) throws JOSEException {
        if (request.secret() == null || request.secret().isBlank()) {
            throw new JwsOperationException("'secret' is required to verify HMAC-signed JWS");
        }
        byte[] keyBytes = request.secret().getBytes(StandardCharsets.UTF_8);
        return new MACVerifier(keyBytes);
    }

    private RSASSAVerifier buildRsaVerifier(JwsVerifyRequest request) {
        if (request.publicKey() == null || request.publicKey().isBlank()) {
            throw new JwsOperationException("'publicKey' is required to verify RSA-signed JWS");
        }
        RSAPublicKey publicKey = (RSAPublicKey) parseX509PublicKey(request.publicKey(), "RSA");
        return new RSASSAVerifier(publicKey);
    }

    private ECDSAVerifier buildEcVerifier(JwsVerifyRequest request) throws JOSEException {
        if (request.publicKey() == null || request.publicKey().isBlank()) {
            throw new JwsOperationException("'publicKey' is required to verify EC-signed JWS");
        }
        ECPublicKey publicKey = (ECPublicKey) parseX509PublicKey(request.publicKey(), "EC");
        return new ECDSAVerifier(publicKey);
    }

    // -----------------------------------------------------------------------
    // Private helpers – key parsing
    // -----------------------------------------------------------------------

    private PrivateKey parsePkcs8PrivateKey(String pem, String algorithm) {
        try {
            byte[] keyBytes = decodePem(pem);
            PKCS8EncodedKeySpec spec = new PKCS8EncodedKeySpec(keyBytes);
            return KeyFactory.getInstance(algorithm).generatePrivate(spec);
        } catch (GeneralSecurityException | IllegalArgumentException e) {
            throw new JwsOperationException("Failed to parse " + algorithm + " private key: " + e.getMessage(), e);
        }
    }

    private PublicKey parseX509PublicKey(String pem, String algorithm) {
        try {
            byte[] keyBytes = decodePem(pem);
            X509EncodedKeySpec spec = new X509EncodedKeySpec(keyBytes);
            return KeyFactory.getInstance(algorithm).generatePublic(spec);
        } catch (GeneralSecurityException | IllegalArgumentException e) {
            throw new JwsOperationException("Failed to parse " + algorithm + " public key: " + e.getMessage(), e);
        }
    }

    /**
     * Strips PEM headers/footers and decodes the Base64 content.
     * Also accepts raw Base64 (no PEM headers).
     */
    private byte[] decodePem(String pem) {
        String cleaned = pem
                .replaceAll("-----BEGIN [^-]+-----", "")
                .replaceAll("-----END [^-]+-----", "")
                .replaceAll("\\s+", "");
        return Base64.getDecoder().decode(cleaned);
    }

    // -----------------------------------------------------------------------
    // Private helpers – key-pair generation
    // -----------------------------------------------------------------------

    private KeyGenerateResponse generateRsaKeyPair(Integer requestedSize) {
        int keySize = (requestedSize != null) ? requestedSize : 2048;
        if (keySize != 2048 && keySize != 4096) {
            throw new IllegalArgumentException("RSA keySize must be 2048 or 4096");
        }
        try {
            RSAKey rsaKey = new RSAKeyGenerator(keySize)
                    .keyID(UUID.randomUUID().toString())
                    .generate();

            String privatePem = toPem("PRIVATE KEY", rsaKey.toRSAPrivateKey().getEncoded());
            String publicPem  = toPem("PUBLIC KEY",  rsaKey.toRSAPublicKey().getEncoded());

            return new KeyGenerateResponse("RSA", keySize, privatePem, publicPem);
        } catch (JOSEException e) {
            throw new JwsOperationException("Failed to generate RSA key pair: " + e.getMessage(), e);
        }
    }

    private KeyGenerateResponse generateEcKeyPair(Integer requestedSize) {
        int curveSize = (requestedSize != null) ? requestedSize : 256;
        Curve curve = switch (curveSize) {
            case 256 -> Curve.P_256;
            case 384 -> Curve.P_384;
            case 521 -> Curve.P_521;
            default  -> throw new IllegalArgumentException("EC keySize must be 256, 384, or 521");
        };
        try {
            ECKey ecKey = new ECKeyGenerator(curve)
                    .keyID(UUID.randomUUID().toString())
                    .generate();

            String privatePem = toPem("PRIVATE KEY", ecKey.toECPrivateKey().getEncoded());
            String publicPem  = toPem("PUBLIC KEY",  ecKey.toECPublicKey().getEncoded());

            return new KeyGenerateResponse("EC", curveSize, privatePem, publicPem);
        } catch (JOSEException e) {
            throw new JwsOperationException("Failed to generate EC key pair: " + e.getMessage(), e);
        }
    }

    private String toPem(String label, byte[] encoded) {
        String base64 = Base64.getMimeEncoder(64, new byte[]{'\n'}).encodeToString(encoded);
        return """
                -----BEGIN %s-----
                %s
                -----END %s-----
                """.formatted(label, base64, label);
    }
}
