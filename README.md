# RFC 3161 Timestamp Server

A compliant RFC 3161 Timestamp Server implementation using Spring Boot and Kotlin.

## Overview

This service provides timestamp tokens following the RFC 3161 standard. It includes the following features:

- Creating timestamp tokens for hashed documents
- Verification of timestamp tokens
- Health and info endpoints
- Docker support

## Prerequisites

- JDK 21
- Gradle
- Docker (for containerized deployment)

## Running the Application

### Using Gradle

```bash
./gradlew bootRun
```

### Using Docker

```bash
docker-compose up --build
```

## API Endpoints

- `POST /api/v1/timestamp` - Create a timestamp token
- `POST /api/v1/verify` - Verify a timestamp token
- `POST /api/v1/verify/data` - Verify with original data
- `GET /api/v1/timestamp/info` - Get timestamp info
- `GET /api/v1/info` - Get TSA server info
- `GET /api/v1/health` - Health check

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

A Postman collection is provided in the `postman` directory for testing the API endpoints.