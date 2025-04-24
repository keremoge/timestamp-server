package com.albaraka.tsa.timestampserver.config

import com.albaraka.tsa.timestampserver.service.KeyStoreService
import org.mockito.Mockito
import org.springframework.boot.test.context.TestConfiguration
import org.springframework.context.annotation.Bean
import org.springframework.context.annotation.Primary

@TestConfiguration
class TestConfig {
    
    @Bean
    @Primary
    fun keyStoreService(): KeyStoreService {
        return Mockito.mock(KeyStoreService::class.java)
    }
}