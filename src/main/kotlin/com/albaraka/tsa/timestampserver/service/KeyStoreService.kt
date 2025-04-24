package com.albaraka.tsa.timestampserver.service

import com.albaraka.tsa.timestampserver.config.TsaConfig
import org.bouncycastle.cert.X509CertificateHolder
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter
import org.bouncycastle.jce.provider.BouncyCastleProvider
import org.bouncycastle.openssl.PEMKeyPair
import org.bouncycastle.openssl.PEMParser
import org.bouncycastle.openssl.jcajce.JcaPEMKeyConverter
import org.bouncycastle.pkcs.PKCS8EncryptedPrivateKeyInfo
import org.slf4j.LoggerFactory
import org.springframework.core.io.ClassPathResource
import org.springframework.core.io.ResourceLoader
import org.springframework.stereotype.Service
import java.io.*
import java.nio.file.Files
import java.nio.file.Paths
import java.security.*
import java.security.cert.Certificate
import java.security.cert.CertificateFactory
import java.security.cert.X509Certificate
import org.bouncycastle.asn1.pkcs.PrivateKeyInfo
import org.bouncycastle.util.io.pem.PemReader

@Service
class KeyStoreService(
    private val tsaConfig: TsaConfig,
    private val resourceLoader: ResourceLoader
) {
    private val logger = LoggerFactory.getLogger(KeyStoreService::class.java)
    private lateinit var keyStore: KeyStore
    private var initialized = false

    companion object {
        private const val DOCKER_SECRETS_PATH = "/run/secrets/"
        private const val CERT_SECRET_NAME = "tsa_cert"
        private const val KEY_SECRET_NAME = "tsa_key"
        private const val DEFAULT_CERT_PATH = "certificates/tsa.crt"
        private const val DEFAULT_KEY_PATH = "certificates/tsa.key"
    }

    init {
        Security.addProvider(BouncyCastleProvider())
        try {
            initializeKeyStore()
        } catch (e: Exception) {
            logger.error("Failed to initialize keystore", e)
            throw e
        }
    }

    private fun initializeKeyStore() {
        try {
            keyStore = KeyStore.getInstance("JKS")
            keyStore.load(null, tsaConfig.certificates.keystore.password.toCharArray())
            
            // Try to load certificates in order:
            // 1. From Docker secrets
            // 2. From project files
            
            if (loadFromDockerSecrets()) {
                logger.info("Successfully loaded certificates from Docker secrets")
            } else if (loadFromProjectFiles()) {
                logger.info("Successfully loaded certificates from project files")
            } else {
                throw IllegalStateException("No certificates found in Docker secrets or project files")
            }
            
            initialized = true
            logger.info("KeyStore initialized successfully")
        } catch (e: Exception) {
            logger.error("Error initializing keystore", e)
            throw e
        }
    }
    
    private fun loadFromDockerSecrets(): Boolean {
        logger.info("Attempting to load certificates from Docker secrets")
        
        val certFile = File("$DOCKER_SECRETS_PATH$CERT_SECRET_NAME")
        val keyFile = File("$DOCKER_SECRETS_PATH$KEY_SECRET_NAME")
        
        if (!certFile.exists() || !keyFile.exists()) {
            logger.info("Docker secrets not found: ${certFile.absolutePath} or ${keyFile.absolutePath}")
            return false
        }
        
        return try {
            val privateKey = readPrivateKeyFromFile(keyFile)
            val certificate = readCertificateFromFile(certFile)
            
            // Store in keystore
            keyStore.setKeyEntry(
                tsaConfig.certificates.keystore.alias,
                privateKey,
                tsaConfig.certificates.keystore.password.toCharArray(),
                arrayOf(certificate)
            )
            
            true
        } catch (e: Exception) {
            logger.error("Error loading from Docker secrets", e)
            false
        }
    }
    
    private fun loadFromProjectFiles(): Boolean {
        logger.info("Attempting to load certificates from project files")
        
        try {
            // Try to load from resources
            val certResource = resourceLoader.getResource("classpath:$DEFAULT_CERT_PATH")
            val keyResource = resourceLoader.getResource("classpath:$DEFAULT_KEY_PATH")
            
            if (!certResource.exists() || !keyResource.exists()) {
                logger.info("Certificate or key not found in resources")
                return false
            }
            
            val privateKey = keyResource.inputStream.use {
                readPrivateKeyFromStream(it)
            }
            
            val certificate = certResource.inputStream.use {
                readCertificateFromStream(it)
            }
            
            logger.info("Successfully read certificate and private key from resources")
            
            // Store in keystore
            keyStore.setKeyEntry(
                tsaConfig.certificates.keystore.alias,
                privateKey,
                tsaConfig.certificates.keystore.password.toCharArray(),
                arrayOf(certificate)
            )
            
            return true
        } catch (e: Exception) {
            logger.error("Error loading from project files", e)
            return false
        }
    }
    
    private fun readPrivateKeyFromFile(file: File): PrivateKey {
        return FileReader(file).use { reader ->
            readPrivateKeyFromReader(reader)
        }
    }
    
    private fun readPrivateKeyFromStream(stream: InputStream): PrivateKey {
        return InputStreamReader(stream).use { reader ->
            readPrivateKeyFromReader(reader)
        }
    }
    
    private fun readPrivateKeyFromReader(reader: Reader): PrivateKey {
        try {
            val pemParser = PEMParser(reader)
            val pemObject = pemParser.readObject()
            
            val converter = JcaPEMKeyConverter().setProvider(BouncyCastleProvider())
            
            return when (pemObject) {
                is PEMKeyPair -> {
                    logger.info("Processing PEMKeyPair format")
                    converter.getKeyPair(pemObject).private
                }
                is PrivateKeyInfo -> {
                    logger.info("Processing PrivateKeyInfo format")
                    converter.getPrivateKey(pemObject)
                }
                is PKCS8EncryptedPrivateKeyInfo -> {
                    logger.info("Processing PKCS8EncryptedPrivateKeyInfo format")
                    throw IllegalArgumentException("Encrypted private keys are not supported")
                }
                else -> {
                    logger.info("Unknown format, attempting alternate methods")
                    // Try with PemReader as a fallback
                    try {
                        // Need to reset the reader to try again
                        if (reader is BufferedReader) {
                            reader.reset()
                        } else {
                            throw IOException("Reader cannot be reset")
                        }
                    } catch (e: IOException) {
                        throw IllegalArgumentException("Unsupported key format and reader cannot be reset", e)
                    }
                    
                    val pemReader = PemReader(reader)
                    val pemContent = pemReader.readPemObject() ?: throw IllegalArgumentException("Failed to read PEM content")
                    logger.info("Read PEM content with type: ${pemContent.type}")
                    
                    // Try with PKCS#8 format
                    val keyFactory = KeyFactory.getInstance("RSA", BouncyCastleProvider())
                    try {
                        val keySpec = java.security.spec.PKCS8EncodedKeySpec(pemContent.content)
                        keyFactory.generatePrivate(keySpec)
                    } catch (e: Exception) {
                        logger.error("Failed to process as PKCS#8", e)
                        throw IllegalArgumentException("Unsupported key format", e)
                    }
                }
            }
        } catch (e: Exception) {
            logger.error("Error reading private key", e)
            
            // Last resort - try direct PKCS#8 reading
            try {
                // Try to rewind/reset the reader if possible
                try {
                    if (reader is BufferedReader) {
                        reader.reset()
                    } else {
                        // If we can't reset, throw an exception to be caught by the outer catch
                        throw IOException("Reader cannot be reset")
                    }
                } catch (resetEx: IOException) {
                    // If reset fails, we'll create a new reader from scratch in the calling method
                    throw resetEx
                }
                
                val pemReader = PemReader(reader)
                val pemContent = pemReader.readPemObject() ?: throw IllegalArgumentException("Failed to read PEM content")
                
                val keyFactory = KeyFactory.getInstance("RSA", BouncyCastleProvider())
                return keyFactory.generatePrivate(java.security.spec.PKCS8EncodedKeySpec(pemContent.content))
            } catch (innerEx: Exception) {
                logger.error("All key parsing methods failed", innerEx)
                throw IllegalArgumentException("Unsupported key format", e)
            }
        }
    }
    
    private fun readCertificateFromFile(file: File): X509Certificate {
        return FileInputStream(file).use { stream ->
            readCertificateFromStream(stream)
        }
    }
    
    private fun readCertificateFromStream(stream: InputStream): X509Certificate {
        val certFactory = CertificateFactory.getInstance("X.509")
        return certFactory.generateCertificate(stream) as X509Certificate
    }

    fun getSigningKey(): PrivateKey {
        if (!initialized) {
            throw IllegalStateException("KeyStore not initialized")
        }
        
        return keyStore.getKey(
            tsaConfig.certificates.keystore.alias,
            tsaConfig.certificates.keystore.password.toCharArray()
        ) as PrivateKey
    }

    fun getSigningCertificate(): X509Certificate {
        if (!initialized) {
            throw IllegalStateException("KeyStore not initialized")
        }
        
        return keyStore.getCertificate(tsaConfig.certificates.keystore.alias) as X509Certificate
    }

    fun getSigningCertificateChain(): Array<Certificate> {
        if (!initialized) {
            throw IllegalStateException("KeyStore not initialized")
        }
        
        return keyStore.getCertificateChain(tsaConfig.certificates.keystore.alias)
    }

    fun sign(data: ByteArray): ByteArray {
        val signature = Signature.getInstance("SHA256withRSA", BouncyCastleProvider())
        signature.initSign(getSigningKey())
        signature.update(data)
        return signature.sign()
    }

    fun verify(data: ByteArray, signatureBytes: ByteArray): Boolean {
        val signature = Signature.getInstance("SHA256withRSA", BouncyCastleProvider())
        signature.initVerify(getSigningCertificate())
        signature.update(data)
        return signature.verify(signatureBytes)
    }
}