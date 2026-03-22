# JWS Generator

A **Spring Boot 3.x** application that generates, verifies, and manages keys for **JSON Web Signatures (JWS)** as defined by [RFC 7515](https://datatracker.ietf.org/doc/html/rfc7515).

## Features

| Feature | Details |
|---|---|
| **Generate JWS** | Creates a compact JWS serialization (`header.payload.signature`) |
| **Verify JWS** | Validates an existing JWS and returns the decoded payload |
| **Generate Key Pair** | Generates RSA or EC key pairs in PEM format |

### Supported Algorithms

| Family | Algorithms |
|---|---|
| HMAC | `HS256`, `HS384`, `HS512` |
| RSA | `RS256`, `RS384`, `RS512` |
| ECDSA | `ES256`, `ES384`, `ES512` |

## Requirements

- Java 17+
- Maven 3.9+

## Running the Application

```bash
./mvnw spring-boot:run
```

The server starts on `http://localhost:8080`.

---

## API Reference

### Generate a JWS

**POST** `/api/v1/jws/generate`

#### HMAC (HS256)

```bash
curl -X POST http://localhost:8080/api/v1/jws/generate \
  -H "Content-Type: application/json" \
  -d '{
    "algorithm": "HS256",
    "payload": "{\"sub\": \"1234567890\", \"name\": \"John Doe\"}",
    "secret": "my-very-long-secret-key"
  }'
```

**Response (201 Created)**

```json
{
  "jws": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpPU0UifQ.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIn0.xxx",
  "algorithm": "HS256",
  "header": "{\"alg\":\"HS256\",\"typ\":\"JOSE\"}",
  "payload": "{\"sub\": \"1234567890\", \"name\": \"John Doe\"}"
}
```

#### RSA (RS256) — first generate a key pair

```bash
# 1. Generate RSA key pair
curl -X POST http://localhost:8080/api/v1/keys/generate \
  -H "Content-Type: application/json" \
  -d '{"algorithm": "RSA", "keySize": 2048}'

# 2. Use the returned privateKey to sign
curl -X POST http://localhost:8080/api/v1/jws/generate \
  -H "Content-Type: application/json" \
  -d '{
    "algorithm": "RS256",
    "payload": "{\"sub\": \"user-1\"}",
    "privateKey": "-----BEGIN PRIVATE KEY-----\n...\n-----END PRIVATE KEY-----\n"
  }'
```

#### ECDSA (ES256)

```bash
# 1. Generate EC key pair (P-256)
curl -X POST http://localhost:8080/api/v1/keys/generate \
  -H "Content-Type: application/json" \
  -d '{"algorithm": "EC", "keySize": 256}'

# 2. Sign with the private key
curl -X POST http://localhost:8080/api/v1/jws/generate \
  -H "Content-Type: application/json" \
  -d '{
    "algorithm": "ES256",
    "payload": "{\"iss\": \"myapp\"}",
    "privateKey": "-----BEGIN PRIVATE KEY-----\n...\n-----END PRIVATE KEY-----\n"
  }'
```

#### Optional: custom headers

```json
{
  "algorithm": "HS256",
  "payload": "{\"sub\": \"1\"}",
  "secret": "long-enough-secret",
  "headers": {
    "kid": "my-key-id"
  }
}
```

---

### Verify a JWS

**POST** `/api/v1/jws/verify`

```bash
curl -X POST http://localhost:8080/api/v1/jws/verify \
  -H "Content-Type: application/json" \
  -d '{
    "jws": "eyJ...",
    "secret": "my-very-long-secret-key"
  }'
```

For RSA/EC JWS, provide `publicKey` instead of `secret`.

**Response (200 OK)**

```json
{
  "valid": true,
  "header": "{\"alg\":\"HS256\",\"typ\":\"JOSE\"}",
  "payload": "{\"sub\": \"1234567890\", \"name\": \"John Doe\"}",
  "message": "Signature is valid"
}
```

---

### Generate a Key Pair

**POST** `/api/v1/keys/generate`

| Field | Type | Values |
|---|---|---|
| `algorithm` | string (required) | `RSA`, `EC` |
| `keySize` | integer (optional) | RSA: `2048` (default), `4096`; EC: `256` (default), `384`, `521` |

```bash
curl -X POST http://localhost:8080/api/v1/keys/generate \
  -H "Content-Type: application/json" \
  -d '{"algorithm": "EC", "keySize": 384}'
```

**Response (201 Created)**

```json
{
  "algorithm": "EC",
  "keySize": 384,
  "privateKey": "-----BEGIN PRIVATE KEY-----\n...\n-----END PRIVATE KEY-----\n",
  "publicKey": "-----BEGIN PUBLIC KEY-----\n...\n-----END PUBLIC KEY-----\n"
}
```

---

## Health Check

```bash
curl http://localhost:8080/actuator/health
```

## Building and Testing

```bash
# Run all tests
./mvnw test

# Build the JAR
./mvnw package

# Run the JAR
java -jar target/jws-generator-0.0.1-SNAPSHOT.jar
```