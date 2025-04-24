package com.albaraka.tsa.timestampserver.controller

import com.albaraka.tsa.timestampserver.model.VerificationRequest
import com.albaraka.tsa.timestampserver.service.TimestampService
import com.albaraka.tsa.timestampserver.service.VerificationService
import org.springframework.http.ResponseEntity
import org.springframework.web.bind.annotation.*
import org.springframework.web.multipart.MultipartFile
import org.slf4j.LoggerFactory

@RestController
@RequestMapping("/api/v1/verify")
class VerificationController(
    private val timestampService: TimestampService,
    private val verificationService: VerificationService
) {
    
    private val logger = LoggerFactory.getLogger(VerificationController::class.java)
    
    @PostMapping
    fun verifyTimestamp(
        @RequestBody request: VerificationRequest
    ): ResponseEntity<Map<String, Any>> {
        logger.info("Received verify request with messageImprint: ${request.messageImprint}")
        val isValid = timestampService.verifyTimestamp(request.timeStampToken, request.messageImprint)
        
        val response = if (isValid) {
            try {
                val timestampInfo = timestampService.getTimestampInfo(request.timeStampToken)
                mapOf(
                    "valid" to true,
                    "timestamp" to (timestampInfo["genTime"] ?: ""),
                    "issuer" to (timestampInfo["issuer"] ?: ""),
                    "serialNumber" to (timestampInfo["serialNumber"] ?: "")
                )
            } catch (e: Exception) {
                mapOf("valid" to true)
            }
        } else {
            mapOf("valid" to false, "errorMessage" to "Timestamp verification failed")
        }
        
        return ResponseEntity.ok(response)
    }
}