package com.albaraka.tsa.timestampserver.config

import org.springframework.boot.context.properties.ConfigurationProperties
import org.springframework.context.annotation.Configuration

@Configuration
@ConfigurationProperties(prefix = "tsa")
class TsaConfig {
    var policy: String = "1.3.6.1.4.1.13762.3"
    var accuracy: AccuracyConfig = AccuracyConfig()
    var certificates: CertificatesConfig = CertificatesConfig()
    var serialNumberLength: Int = 64

    class AccuracyConfig {
        var seconds: Int = 1
        var millis: Int = 0
        var micros: Int = 0
    }

    class CertificatesConfig {
        var keystore: KeystoreConfig = KeystoreConfig()
    }

    class KeystoreConfig {
        var path: String = "classpath:keystore.jks"
        var password: String = "changeit"
        var alias: String = "tsa"
    }
}