package com.albaraka.tsa.timestampserver.model

data class TimestampRequest(
    val version: Int,
    val messageImprint: MessageImprint,
    val reqPolicy: String,
    val nonce: String?,
    val certReq: Boolean,
    val extensions: List<Extension> = emptyList()
)

data class MessageImprint(
    val hashAlgorithm: HashAlgorithm,
    val hashedMessage: String
)

data class HashAlgorithm(
    val algorithm: String,
    val parameters: Any?
)

data class Extension(
    val critical: Boolean,
    val extnID: String,
    val extnValue: Any?
)