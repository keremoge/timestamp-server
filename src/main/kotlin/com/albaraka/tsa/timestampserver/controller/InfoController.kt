package com.albaraka.tsa.timestampserver.controller

import com.albaraka.tsa.timestampserver.config.TsaConfig
import org.springframework.http.ResponseEntity
import org.springframework.web.bind.annotation.GetMapping
import org.springframework.web.bind.annotation.RequestMapping
import org.springframework.web.bind.annotation.RestController
import java.time.Instant

@RestController
@RequestMapping("/api/v1/info")
class InfoController(private val tsaConfig: TsaConfig) {
    
    @GetMapping
    fun getTsaInfo(): ResponseEntity<Map<String, Any>> {
        return ResponseEntity.ok(
            mapOf(
                "serverName" to "RFC 3161 Timestamp Authority",
                "version" to "1.0.0",
                "policy" to tsaConfig.policy,
                "algorithms" to listOf(
                    "SHA-256 (2.16.840.1.101.3.4.2.1)",
                    "SHA-384 (2.16.840.1.101.3.4.2.2)",
                    "SHA-512 (2.16.840.1.101.3.4.2.3)"
                ),
                "accuracy" to mapOf(
                    "seconds" to tsaConfig.accuracy.seconds,
                    "millis" to tsaConfig.accuracy.millis,
                    "micros" to tsaConfig.accuracy.micros
                ),
                "currentTime" to Instant.now().toString()
            )
        )
    }
}