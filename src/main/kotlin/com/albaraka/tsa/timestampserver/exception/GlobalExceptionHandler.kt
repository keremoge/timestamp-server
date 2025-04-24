package com.albaraka.tsa.timestampserver.exception

import org.springframework.http.HttpStatus
import org.springframework.http.ResponseEntity
import org.springframework.web.bind.annotation.ControllerAdvice
import org.springframework.web.bind.annotation.ExceptionHandler
import org.springframework.web.context.request.WebRequest
import org.slf4j.LoggerFactory
import java.time.Instant

@ControllerAdvice
class GlobalExceptionHandler {
    
    private val logger = LoggerFactory.getLogger(GlobalExceptionHandler::class.java)
    
    @ExceptionHandler(Exception::class)
    fun handleAllExceptions(ex: Exception, request: WebRequest): ResponseEntity<ErrorResponse> {
        logger.error("Unhandled exception", ex)
        
        val errorDetails = ErrorResponse(
            timestamp = Instant.now().toString(),
            status = HttpStatus.INTERNAL_SERVER_ERROR.value(),
            error = "Internal Server Error",
            message = ex.message ?: "Unknown error",
            path = request.getDescription(false).replace("uri=", "")
        )
        
        return ResponseEntity(errorDetails, HttpStatus.INTERNAL_SERVER_ERROR)
    }
    
    @ExceptionHandler(IllegalArgumentException::class)
    fun handleIllegalArgumentException(ex: IllegalArgumentException, request: WebRequest): ResponseEntity<ErrorResponse> {
        logger.error("Bad request", ex)
        
        val errorDetails = ErrorResponse(
            timestamp = Instant.now().toString(),
            status = HttpStatus.BAD_REQUEST.value(),
            error = "Bad Request",
            message = ex.message ?: "Invalid input",
            path = request.getDescription(false).replace("uri=", "")
        )
        
        return ResponseEntity(errorDetails, HttpStatus.BAD_REQUEST)
    }
    
    data class ErrorResponse(
        val timestamp: String,
        val status: Int,
        val error: String,
        val message: String,
        val path: String
    )
}