# RFC 3161 Timestamp Server

A compliant RFC 3161 Timestamp Server implementation using Spring Boot and Kotlin.

## Overview

This service provides timestamp tokens following the RFC 3161 standard. It includes the following features:

- Creating timestamp tokens for hashed documents
- Verification of timestamp tokens
- Health and info endpoints
- Docker support
- Secure certificate management
- Standards-compliant implementation

## Prerequisites

- JDK 21
- Gradle
- Docker (for containerized deployment)

## Running the Application

### Using Gradle

```bash
./gradlew bootRun
```

The server will start on port 8080 by default, which can be configured in the application.yml file.

### Using Docker

```bash
docker-compose up --build
```

This will build and run the application in a Docker container with the configurations specified in the docker-compose.yml file.

## Configuration

The application can be configured through:

- `application.yml` - Main configuration file
- `application-docker.yml` - Docker-specific configurations

### Key Configuration Properties

```yml
server:
  port: 8080  # Default server port

tsa:
  info:
    name: "RFC 3161 Timestamp Authority"
    accuracy: 
      seconds: 1
      millis: 0
      micros: 0
    ordering: false
    tsa: "http://timestamp.example.com"
  certificates:
    cert-path: "certificates/tsa.crt"
    key-path: "certificates/tsa.key"
```

## API Endpoints

### Timestamp Creation
- `POST /api/v1/timestamp` - Create a timestamp token
  - Request Body: JSON with base64-encoded hash and optional parameters
  - Response: Base64-encoded timestamp token

### Verification 
- `POST /api/v1/verify` - Verify a timestamp token
  - Request Body: JSON with base64-encoded timestamp token and hash
  - Response: Verification result with details

- `POST /api/v1/verify/data` - Verify with original data
  - Request Body: JSON with base64-encoded timestamp token and original data
  - Response: Verification result with details

### Information and Health
- `GET /api/v1/timestamp/info` - Get timestamp info
  - Response: Details about the timestamp service configuration

- `GET /api/v1/info` - Get TSA server info
  - Response: Server information including version, name, and supported algorithms

- `GET /api/v1/health` - Health check
  - Response: Current server health status

## Usage Examples

### Creating a Timestamp

```bash
curl -X POST http://localhost:8080/api/v1/timestamp \
  -H "Content-Type: application/json" \
  -d '{
    "hash": "BASE64_ENCODED_HASH",
    "hashAlgorithm": "SHA-256"
  }'
```

### Verifying a Timestamp

```bash
curl -X POST http://localhost:8080/api/v1/verify \
  -H "Content-Type: application/json" \
  -d '{
    "token": "BASE64_ENCODED_TOKEN",
    "hash": "BASE64_ENCODED_HASH"
  }'
```

## Certificate Management

The server uses X.509 certificates with the proper extensions for RFC 3161 timestamp signing.

### Generating a Certificate for Development

```bash
openssl req -x509 -newkey rsa:2048 -keyout src/main/resources/certificates/tsa.key -out src/main/resources/certificates/tsa.crt -days 3650 -nodes -subj "/C=US/ST=California/L=Mountain View/O=TSA/OU=TSA/CN=Trusted Timestamp/SN=TS-CA/emailAddress=tsa-ca@example.com" -addext "keyUsage = digitalSignature" -addext "extendedKeyUsage = timeStamping"
```

### Certificate Loading Order

1. First tries to load from Docker secrets: `/run/secrets/tsa_cert` and `/run/secrets/tsa_key`
2. Falls back to project resources: `certificates/tsa.crt` and `certificates/tsa.key`

## Testing with Postman

A Postman collection is provided in the `postman` directory for testing the API endpoints. Import the collection from `postman/Timestamp_Server_API.postman_collection.json` to get started quickly.

## Security Considerations

- Always use proper X.509 certificates with the `timeStamping` extended key usage
- Use secure key storage in production environments
- Consider implementing rate limiting for production deployments

## License

This project is licensed under the MIT License - see the LICENSE file for details.

## Contributing

Contributions are welcome! Please feel free to submit a Pull Request.