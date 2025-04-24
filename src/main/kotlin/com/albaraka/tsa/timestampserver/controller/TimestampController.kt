package com.albaraka.tsa.timestampserver.controller

import com.albaraka.tsa.timestampserver.model.TimestampRequest
import com.albaraka.tsa.timestampserver.model.TimestampResponse
import com.albaraka.tsa.timestampserver.service.TimestampService
import org.springframework.http.ResponseEntity
import org.springframework.web.bind.annotation.*
import org.slf4j.LoggerFactory
import java.util.Base64

@RestController
@RequestMapping("/api/v1/timestamp")
class TimestampController(private val timestampService: TimestampService) {
    
    private val logger = LoggerFactory.getLogger(TimestampController::class.java)
    
    @PostMapping
    fun createTimestamp(@RequestBody request: TimestampRequest): ResponseEntity<TimestampResponse> {
        logger.info("Received timestamp request with hash: ${request.messageImprint.hashedMessage}")
        val response = timestampService.createTimestamp(request)
        return ResponseEntity.ok(response)
    }
    
    @PostMapping("/verify")
    fun verifyTimestamp(@RequestBody request: Map<String, Any>): ResponseEntity<Map<String, Any>> {
        logger.info("Received timestamp verification request")
        
        // Extract token and hash from request
        val token = request["token"] ?: return ResponseEntity.badRequest().body(mapOf("verified" to false, "error" to "Token is required"))
        val hash = request["hash"] as? String ?: return ResponseEntity.badRequest().body(mapOf("verified" to false, "error" to "Hash is required and must be a string"))
        
        val verified = timestampService.verifyTimestamp(token, hash)
        return ResponseEntity.ok(mapOf("verified" to verified))
    }
    
    @PostMapping("/verify-data")
    fun verifyWithOriginalData(@RequestBody request: Map<String, Any>): ResponseEntity<Map<String, Any>> {
        logger.info("Received timestamp verification request with original data")
        
        // Extract token and data from request
        val token = request["token"] ?: return ResponseEntity.badRequest().body(mapOf("verified" to false, "error" to "Token is required"))
        
        val dataString = request["data"] as? String ?: return ResponseEntity.badRequest().body(mapOf("verified" to false, "error" to "Data is required and must be a string"))
        val data = try {
            Base64.getDecoder().decode(dataString)
        } catch (e: Exception) {
            return ResponseEntity.badRequest().body(mapOf("verified" to false, "error" to "Data must be a valid base64 encoded string"))
        }
        
        val hashAlgorithm = request["hashAlgorithm"] as? String ?: "SHA-256"
        
        val verified = timestampService.verifyWithOriginalData(token, data, hashAlgorithm)
        return ResponseEntity.ok(mapOf("verified" to verified))
    }
    
    @PostMapping("/info")
    fun getTimestampInfo(@RequestBody request: Map<String, Any>): ResponseEntity<Map<String, Any>> {
        logger.info("Received request for timestamp info")
        val token = request["token"] ?: return ResponseEntity.badRequest().body(mapOf("error" to "Token is required"))
        val info = timestampService.getTimestampInfo(token)
        return ResponseEntity.ok(info)
    }
    
    @GetMapping("/info")
    fun getTimestampInfoGet(@RequestParam token: String): ResponseEntity<Map<String, Any>> {
        logger.info("Received GET request for timestamp info")
        val info = timestampService.getTimestampInfo(token)
        return ResponseEntity.ok(info)
    }
}