package com.albaraka.tsa.timestampserver.service

import com.albaraka.tsa.timestampserver.config.TsaConfig
import com.albaraka.tsa.timestampserver.model.*
import com.fasterxml.jackson.databind.ObjectMapper
import org.bouncycastle.asn1.ASN1ObjectIdentifier
import org.bouncycastle.asn1.x500.X500Name
import org.bouncycastle.cert.jcajce.JcaX509CertificateHolder
import org.bouncycastle.cms.CMSSignedData
import org.bouncycastle.tsp.TimeStampToken
import org.bouncycastle.util.encoders.Hex
import org.springframework.stereotype.Service
import java.math.BigInteger
import java.security.MessageDigest
import java.security.SecureRandom
import java.time.Instant
import java.time.ZoneOffset
import java.time.format.DateTimeFormatter
import java.util.Base64
import org.slf4j.LoggerFactory
import org.springframework.beans.factory.annotation.Autowired

@Service
class TimestampService(
    private val tsaConfig: TsaConfig,
    private val keyStoreService: KeyStoreService,
    @Autowired private val objectMapper: ObjectMapper
) {
    
    private val logger = LoggerFactory.getLogger(TimestampService::class.java)
    private val secureRandom = SecureRandom()
    
    fun createTimestamp(request: TimestampRequest): TimestampResponse {
        logger.info("Creating timestamp for request with hash: ${request.messageImprint.hashedMessage}")
        
        try {
            // Generate serialNumber using secure random
            val serialNumber = BigInteger(tsaConfig.serialNumberLength, secureRandom).toString()
            // Get current time formatted according to RFC 3161
            val genTime = DateTimeFormatter.ISO_INSTANT.format(Instant.now())
            
            // Create the timestamp token info structure
            val tstInfo = TSTInfo(
                version = 1,
                policy = request.reqPolicy,
                messageImprint = request.messageImprint,
                serialNumber = serialNumber,
                genTime = genTime,
                accuracy = Accuracy(
                    seconds = tsaConfig.accuracy.seconds,
                    millis = tsaConfig.accuracy.millis,
                    micros = tsaConfig.accuracy.micros
                ),
                ordering = false,
                nonce = request.nonce,
                tsa = createTsaFromCertificate(),
                extensions = emptyList()
            )
            
            // In a real implementation, we would format the TSTInfo as ASN.1 and sign it
            // For this example, we'll convert it to a JSON string and sign that
            val tstInfoString = tstInfo.toString()
            val signatureBytes = keyStoreService.sign(tstInfoString.toByteArray())
            val signatureHex = Hex.toHexString(signatureBytes)
            
            // Calculate digest of TSTInfo to include in signed attributes
            val digestBytes = MessageDigest.getInstance("SHA-256").digest(tstInfoString.toByteArray())
            val digestHex = Hex.toHexString(digestBytes)
            
            // Get certificate information
            val cert = keyStoreService.getSigningCertificate()
            val certHolder = JcaX509CertificateHolder(cert)
            val issuerX500Name = certHolder.issuer
            
            return TimestampResponse(
                status = Status(0, listOf("Operation Successful"), null),
                timeStampToken = TimeStampToken(
                    contentType = "1.2.840.113549.1.7.2", // id-signedData
                    content = Content(
                        version = 3,
                        digestAlgorithms = listOf(request.messageImprint.hashAlgorithm),
                        encapContentInfo = EncapContentInfo(
                            eContentType = "1.2.840.113549.1.9.16.1.4", // id-ct-TSTInfo
                            eContent = EContent(tstInfo = tstInfo)
                        ),
                        certificates = if (request.certReq) {
                            listOf(generateCertificateFromX509(cert, issuerX500Name))
                        } else {
                            emptyList()
                        },
                        crls = emptyList(),
                        signerInfos = listOf(
                            SignerInfo(
                                version = 1,
                                sid = SID(
                                    issuerAndSerialNumber = IssuerAndSerialNumber(
                                        issuer = createIssuerFromX500Name(issuerX500Name),
                                        serialNumber = cert.serialNumber.toString()
                                    )
                                ),
                                digestAlgorithm = HashAlgorithm(
                                    algorithm = "2.16.840.1.101.3.4.2.1", // SHA-256
                                    parameters = null
                                ),
                                signedAttrs = listOf(
                                    Attribute(
                                        attrType = "1.2.840.113549.1.9.3", // ContentType
                                        attrValues = listOf("1.2.840.113549.1.9.16.1.4") // id-ct-TSTInfo
                                    ),
                                    Attribute(
                                        attrType = "1.2.840.113549.1.9.4", // MessageDigest
                                        attrValues = listOf(digestHex)
                                    ),
                                    Attribute(
                                        attrType = "1.2.840.113549.1.9.5", // SigningTime
                                        attrValues = listOf(DateTimeFormatter.ofPattern("yyyyMMddHHmmss'Z'")
                                            .withZone(ZoneOffset.UTC)
                                            .format(Instant.now()))
                                    )
                                ),
                                signatureAlgorithm = HashAlgorithm(
                                    algorithm = "1.2.840.113549.1.1.11", // SHA256withRSA
                                    parameters = null
                                ),
                                signature = signatureHex,
                                unsignedAttrs = emptyList()
                            )
                        )
                    )
                )
            )
        } catch (e: Exception) {
            logger.error("Error creating timestamp", e)
            return TimestampResponse(
                status = Status(2, listOf("Timestamp creation failed: ${e.message}"), "1"), // systemFailure
                timeStampToken = null
            )
        }
    }
    
    fun verifyTimestamp(token: Any, hash: String): Boolean {
        logger.info("Verifying timestamp token with hash: $hash")
        
        try {
            // Check if token is already a TimestampResponse object
            val tokenBytes = when (token) {
                is String -> {
                    try {
                        // First try to interpret as direct JSON
                        token.toByteArray()
                    } catch (e: Exception) {
                        try {
                            // If that fails, try base64 decoding
                            logger.debug("Trying to decode token as base64")
                            Base64.getDecoder().decode(token)
                        } catch (e2: Exception) {
                            logger.error("Failed to decode token as base64", e2)
                            throw e2
                        }
                    }
                }
                is Map<*, *> -> {
                    // Convert map to JSON string
                    objectMapper.writeValueAsBytes(token)
                }
                else -> {
                    // Try to convert object to JSON
                    objectMapper.writeValueAsBytes(token)
                }
            }
            
            // Extract the hash from the token
            val tokenHash = extractHashFromToken(tokenBytes)
            
            // Compare the extracted hash with the provided hash
            if (!tokenHash.equals(hash, ignoreCase = true)) {
                logger.warn("Hash mismatch in verification: token=$tokenHash, provided=$hash")
                return false
            }
            
            // Extract and verify the signature
            return verifyTokenSignature(tokenBytes)
        } catch (e: Exception) {
            logger.error("Error verifying timestamp", e)
            return false
        }
    }
    
    fun verifyWithOriginalData(token: Any, data: ByteArray, hashAlgorithm: String): Boolean {
        try {
            // Compute hash of original data
            val digest = MessageDigest.getInstance(hashAlgorithm)
            val hash = Hex.toHexString(digest.digest(data))
            
            // Verify the timestamp using the computed hash
            return verifyTimestamp(token, hash)
        } catch (e: Exception) {
            logger.error("Error verifying timestamp with original data", e)
            return false
        }
    }
    
    fun getTimestampInfo(token: Any): Map<String, Any> {
        logger.info("Getting timestamp info for token")
        
        try {
            // Convert token to bytes based on its type
            val tokenBytes = when (token) {
                is String -> {
                    try {
                        token.toByteArray()
                    } catch (e: Exception) {
                        try {
                            Base64.getDecoder().decode(token)
                        } catch (e2: Exception) {
                            logger.error("Failed to decode token", e2)
                            throw e2
                        }
                    }
                }
                is Map<*, *> -> {
                    objectMapper.writeValueAsBytes(token)
                }
                else -> {
                    objectMapper.writeValueAsBytes(token)
                }
            }

            // In a real implementation, you would parse the token and extract information
            // For this example, we'll return information from the signing certificate
            val cert = keyStoreService.getSigningCertificate()
            
            return mapOf(
                "issuer" to cert.issuerX500Principal.name,
                "validFrom" to DateTimeFormatter.ISO_INSTANT.format(cert.notBefore.toInstant()),
                "validTo" to DateTimeFormatter.ISO_INSTANT.format(cert.notAfter.toInstant()),
                "serialNumber" to cert.serialNumber.toString(),
                "policy" to tsaConfig.policy,
                "hashAlgorithm" to "SHA-256",
                "signatureAlgorithm" to cert.sigAlgName
            )
        } catch (e: Exception) {
            logger.error("Error getting timestamp info", e)
            throw e
        }
    }
    
    // Helper methods
    private fun createTsaFromCertificate(): TSA {
        val cert = keyStoreService.getSigningCertificate()
        val x500name = JcaX509CertificateHolder(cert).subject
        val rdns = mutableListOf<RDN>()
        
        // Extract and convert X.500 name components
        val rdnSequence = x500name.getRDNs()
        
        // Map BC style OIDs to our model format
        for (rdn in rdnSequence) {
            val firstAVA = rdn.getFirst()
            val type = firstAVA.type.id
            val value = firstAVA.value.toString()
            
            rdns.add(RDN(type = type, value = value))
        }
        
        return TSA(rdnSequence = rdns)
    }
    
    private fun createIssuerFromX500Name(x500Name: X500Name): Issuer {
        val rdns = mutableListOf<RDN>()
        
        // Extract and convert X.500 name components
        val rdnSequence = x500Name.getRDNs()
        
        // Map BC style OIDs to our model format
        for (rdn in rdnSequence) {
            val firstAVA = rdn.getFirst()
            val type = firstAVA.type.id
            val value = firstAVA.value.toString()
            
            rdns.add(RDN(type = type, value = value))
        }
        
        return Issuer(rdnSequence = rdns)
    }
    
    private fun generateCertificateFromX509(cert: java.security.cert.X509Certificate, issuer: X500Name): Certificate {
        return Certificate(
            tbsCertificate = TBSCertificate(
                version = 2,
                serialNumber = cert.serialNumber.toString(),
                signature = HashAlgorithm(
                    algorithm = "1.2.840.113549.1.1.11", // SHA256withRSA
                    parameters = null
                ),
                issuer = createIssuerFromX500Name(issuer),
                validity = Validity(
                    notBefore = TimeValue(generalTime = DateTimeFormatter
                        .ofPattern("yyyyMMddHHmmss'Z'")
                        .withZone(ZoneOffset.UTC)
                        .format(cert.notBefore.toInstant())),
                    notAfter = TimeValue(generalTime = DateTimeFormatter
                        .ofPattern("yyyyMMddHHmmss'Z'")
                        .withZone(ZoneOffset.UTC)
                        .format(cert.notAfter.toInstant()))
                ),
                subject = Subject(
                    rdnSequence = createIssuerFromX500Name(JcaX509CertificateHolder(cert).subject).rdnSequence
                ),
                subjectPublicKeyInfo = SubjectPublicKeyInfo(
                    algorithm = HashAlgorithm(
                        algorithm = "1.2.840.113549.1.1.1", // RSA
                        parameters = null
                    ),
                    subjectPublicKey = Base64.getEncoder().encodeToString(cert.publicKey.encoded)
                ),
                extensions = listOf(
                    Extension(
                        extnID = "2.5.29.15", // Key Usage
                        critical = true,
                        extnValue = "03020780" // digitalSignature
                    ),
                    Extension(
                        extnID = "2.5.29.37", // Extended Key Usage
                        critical = true,
                        extnValue = "300a06082b06010505070308" // timeStamping
                    )
                )
            ),
            signatureAlgorithm = HashAlgorithm(
                algorithm = "1.2.840.113549.1.1.11", // SHA256withRSA
                parameters = null
            ),
            signatureValue = Base64.getEncoder().encodeToString(cert.signature)
        )
    }
    
    // Actual implementations for token parsing
    private fun extractHashFromToken(tokenBytes: ByteArray): String {
        try {
            // Parse the token data
            // In a real implementation with ASN.1 structures:
            val cmsSignedData = CMSSignedData(tokenBytes)
            val timeStampToken = TimeStampToken(cmsSignedData)
            val tstInfo = timeStampToken.timeStampInfo
            
            // Get the hashed message from the TSTInfo
            return Hex.toHexString(tstInfo.getMessageImprintDigest())
        } catch (e: Exception) {
            // If we can't parse as ASN.1, try parsing as our JSON format
            try {
                val tokenString = String(tokenBytes)
                val timeStampResponse = objectMapper.readValue(tokenString, TimestampResponse::class.java)
                return timeStampResponse.timeStampToken?.content?.encapContentInfo?.eContent?.tstInfo?.messageImprint?.hashedMessage
                    ?: throw IllegalArgumentException("No message imprint found in token")
            } catch (jsonEx: Exception) {
                logger.error("Failed to parse token", jsonEx)
                throw jsonEx
            }
        }
    }
    
    private fun verifyTokenSignature(tokenBytes: ByteArray): Boolean {
        try {
            // In a real implementation with ASN.1 structures:
            val cmsSignedData = CMSSignedData(tokenBytes)
            val timeStampToken = TimeStampToken(cmsSignedData)
            
            // Get the signer information from signerInfos collection
            val signers = timeStampToken.toCMSSignedData().signerInfos
            if (signers.size() == 0) {
                logger.error("No signer information found in token")
                return false
            }
            
            // Get the first signer
            val signerInfo = signers.iterator().next()
            
            // Create a JcaSimpleSignerInfoVerifier
            val verifier = org.bouncycastle.cms.jcajce.JcaSimpleSignerInfoVerifierBuilder()
                .setProvider(org.bouncycastle.jce.provider.BouncyCastleProvider())
                .build(keyStoreService.getSigningCertificate())
                
            // Verify the signature using the signer info
            return signerInfo.verify(verifier)
            
        } catch (e: Exception) {
            logger.error("Failed to verify ASN.1 token signature", e)
            
            // If we can't parse as ASN.1, try our own verification method
            try {
                val tokenString = String(tokenBytes)
                val timeStampResponse = objectMapper.readValue(tokenString, TimestampResponse::class.java)
                
                if (timeStampResponse.timeStampToken == null) {
                    return false
                }
                
                // Extract the signed data (TSTInfo)
                val tstInfo = timeStampResponse.timeStampToken.content.encapContentInfo.eContent.tstInfo
                val tstInfoBytes = objectMapper.writeValueAsBytes(tstInfo)
                
                // Extract the signature
                val signature = timeStampResponse.timeStampToken.content.signerInfos.firstOrNull()?.signature
                    ?: return false
                
                // Verify the signature
                val signatureBytes = Hex.decode(signature)
                return keyStoreService.verify(tstInfoBytes, signatureBytes)
            } catch (jsonEx: Exception) {
                logger.error("Failed to verify token signature", jsonEx)
                return false
            }
        }
    }
    
    private fun extractSignedDataFromToken(tokenBytes: ByteArray): ByteArray {
        try {
            // In a real implementation with ASN.1 structures:
            val cmsSignedData = CMSSignedData(tokenBytes)
            val timeStampToken = TimeStampToken(cmsSignedData)
            return timeStampToken.timeStampInfo.encoded
        } catch (e: Exception) {
            // If we can't parse as ASN.1, try our own extraction method
            try {
                val tokenString = String(tokenBytes)
                val timeStampResponse = objectMapper.readValue(tokenString, TimestampResponse::class.java)
                
                if (timeStampResponse.timeStampToken == null) {
                    throw IllegalArgumentException("No timestamp token found")
                }
                
                // Extract the TSTInfo and convert to bytes
                val tstInfo = timeStampResponse.timeStampToken.content.encapContentInfo.eContent.tstInfo
                return objectMapper.writeValueAsBytes(tstInfo)
            } catch (jsonEx: Exception) {
                logger.error("Failed to extract signed data from token", jsonEx)
                throw jsonEx
            }
        }
    }
}