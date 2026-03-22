# JWS Generator

A **Spring Boot 3.x** application that generates, verifies, and manages keys for **JSON Web Signatures (JWS)** as defined by [RFC 7515](https://datatracker.ietf.org/doc/html/rfc7515).

Built with **Java 21** features including virtual threads, text blocks, switch expressions, and records.

## Features

| Feature | Details |
|---|---|
| **Generate JWS** | Creates a compact JWS serialization (`header.payload.signature`) |
| **Verify JWS** | Validates an existing JWS and returns the decoded payload |
| **Generate Key Pair** | Generates RSA or EC key pairs in PEM format |
| **Interactive API Documentation** | Swagger UI for exploring and testing endpoints |
| **Virtual Threads** | Enhanced concurrency with Java 21 virtual threads |

### Supported Algorithms

| Family | Algorithms |
|---|---|
| HMAC | `HS256`, `HS384`, `HS512` |
| RSA | `RS256`, `RS384`, `RS512` |
| ECDSA | `ES256`, `ES384`, `ES512` |

## Requirements

- Java 21+
- Maven 3.9+

## Running the Application

```bash
./mvnw spring-boot:run
```

The server starts on `http://localhost:8080`.

### Interactive API Documentation

Once the application is running, access the **Swagger UI** at:

```
http://localhost:8080/swagger-ui.html
```

Or view the OpenAPI specification (JSON) at:

```
http://localhost:8080/api-docs
```

#### Using Swagger UI

The Swagger UI provides an interactive interface to explore all endpoints, view request/response schemas, and test the API directly from your browser.

**Key Features:**
- **Explore Endpoints**: Browse all available API operations organized by tags
- **View Schemas**: See detailed request/response models with field descriptions and examples
- **Try It Out**: Execute API calls directly from the browser with sample data
- **Authentication**: Test secured endpoints if authentication is configured
- **Response Inspection**: View actual responses including headers, status codes, and bodies

**How to Test an Endpoint:**

1. **Navigate to Swagger UI** at `http://localhost:8080/swagger-ui.html`
2. **Expand an endpoint** by clicking on it (e.g., `POST /api/v1/jws/generate`)
3. **Click "Try it out"** button in the top right of the endpoint section
4. **Fill in the request body** with your test data. Swagger provides example values you can use or modify:
   ```json
   {
     "algorithm": "HS256",
     "payload": "{\"sub\":\"1234567890\",\"name\":\"John Doe\"}",
     "secret": "my-very-long-secret-key"
   }
   ```
5. **Click "Execute"** to send the request
6. **View the response** below, including:
   - HTTP status code (e.g., `201 Created`)
   - Response headers
   - Response body with syntax highlighting
   - cURL command equivalent

**Example Workflow - Generate and Verify a JWS:**

1. First, generate a key pair using `POST /api/v1/keys/generate`:
   - Algorithm: `RSA`
   - Key Size: `2048`
   - Copy the `privateKey` and `publicKey` from the response

2. Generate a JWS using `POST /api/v1/jws/generate`:
   - Algorithm: `RS256`
   - Payload: Your JSON data
   - Private Key: Paste the private key from step 1
   - Copy the `jws` token from the response

3. Verify the JWS using `POST /api/v1/jws/verify`:
   - JWS: Paste the token from step 2
   - Public Key: Paste the public key from step 1
   - Confirm the response shows `"valid": true`

This interactive approach is ideal for development, testing, and API exploration without needing external tools like Postman or curl.

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

## Java 21 Features

This application leverages modern Java 21 features for improved performance, readability, and maintainability:

### Virtual Threads
- **Enabled by default** via `spring.threads.virtual.enabled=true`
- Provides lightweight concurrency for improved throughput
- Seamlessly handles many concurrent requests with reduced resource overhead

### Records
- All DTOs use **record types** for immutable data carriers
- Examples: `JwsRequest`, `JwsResponse`, `KeyGenerateRequest`, etc.
- Provides automatic implementations of `equals()`, `hashCode()`, `toString()`

### Switch Expressions
- **Pattern matching** in switch statements for algorithm resolution
- More concise and type-safe than traditional switch statements
- Example: Algorithm type dispatching in `JwsService`

### Text Blocks
- Multi-line string literals for PEM formatting
- Improved readability for formatted output
- Example: PEM key generation with proper formatting

### Enhanced Exception Handling
- **Multi-catch** with specific exception types
- Better error messages and type safety
- Replaces generic `Exception` catches with `GeneralSecurityException | IllegalArgumentException`

### OpenAPI 3.0 Annotations
- Comprehensive API documentation with `@Schema` annotations
- Interactive Swagger UI for API exploration
- Better developer experience with inline examples and descriptions

## License

This project is licensed under the Apache License 2.0.