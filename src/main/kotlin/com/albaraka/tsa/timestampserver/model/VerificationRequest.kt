package com.albaraka.tsa.timestampserver.model

import com.fasterxml.jackson.annotation.JsonProperty

data class VerificationRequest(
    val timeStampToken: Any, // Changed from String to Any to accept both String and Object
    val messageImprint: String
)