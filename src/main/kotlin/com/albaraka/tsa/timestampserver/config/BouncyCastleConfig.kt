package com.albaraka.tsa.timestampserver.config

import org.bouncycastle.jce.provider.BouncyCastleProvider
import org.springframework.context.annotation.Bean
import org.springframework.context.annotation.Configuration
import java.security.Security

@Configuration
class BouncyCastleConfig {

    @Bean
    fun bouncyCastleProvider(): BouncyCastleProvider {
        val provider = BouncyCastleProvider()
        Security.addProvider(provider)
        return provider
    }
}