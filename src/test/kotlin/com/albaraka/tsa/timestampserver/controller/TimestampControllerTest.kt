package com.albaraka.tsa.timestampserver.controller

import com.albaraka.tsa.timestampserver.model.*
import com.albaraka.tsa.timestampserver.service.KeyStoreService
import com.albaraka.tsa.timestampserver.service.TimestampService
import com.fasterxml.jackson.databind.ObjectMapper
import com.ninjasquad.springmockk.MockkBean
import io.mockk.every
import org.junit.jupiter.api.Test
import org.springframework.beans.factory.annotation.Autowired
import org.springframework.boot.test.autoconfigure.web.servlet.WebMvcTest
import org.springframework.http.MediaType
import org.springframework.test.web.servlet.MockMvc
import org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post
import org.springframework.test.web.servlet.result.MockMvcResultMatchers.status
import org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath

@WebMvcTest(TimestampController::class)
class TimestampControllerTest {

    @Autowired
    private lateinit var mockMvc: MockMvc

    @MockkBean
    private lateinit var timestampService: TimestampService
    
    @MockkBean
    private lateinit var keyStoreService: KeyStoreService

    @Autowired
    private lateinit var objectMapper: ObjectMapper

    @Test
    fun `should create timestamp`() {
        // Given
        val request = TimestampRequest(
            version = 1,
            messageImprint = MessageImprint(
                hashAlgorithm = HashAlgorithm(
                    algorithm = "2.16.840.1.101.3.4.2.1",
                    parameters = null
                ),
                hashedMessage = "3a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0c1d2e3f4a5b6c7d8e9f0a1b"
            ),
            reqPolicy = "1.3.6.1.4.1.13762.3",
            nonce = "9b1deb4d3b7d4bad9bdd2b0d7b3dcb6d",
            certReq = true
        )

        val response = TimestampResponse(
            status = Status(0, listOf("Operation Successful"), null),
            timeStampToken = null
        )

        every { timestampService.createTimestamp(any()) } returns response

        // When/Then
        mockMvc.perform(
            post("/api/v1/timestamp")
                .contentType(MediaType.APPLICATION_JSON)
                .content(objectMapper.writeValueAsString(request))
        )
            .andExpect(status().isOk)
            .andExpect(jsonPath("$.status.status").value(0))
            .andExpect(jsonPath("$.status.statusString[0]").value("Operation Successful"))
    }
}