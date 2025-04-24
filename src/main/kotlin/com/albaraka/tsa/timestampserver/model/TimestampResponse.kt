package com.albaraka.tsa.timestampserver.model

data class TimestampResponse(
    val status: Status,
    val timeStampToken: TimeStampToken?
)

data class Status(
    val status: Int,
    val statusString: List<String>,
    val failInfo: String?
)

data class TimeStampToken(
    val contentType: String,
    val content: Content
)

data class Content(
    val version: Int,
    val digestAlgorithms: List<HashAlgorithm>,
    val encapContentInfo: EncapContentInfo,
    val certificates: List<Certificate>,
    val crls: List<Any>,
    val signerInfos: List<SignerInfo>
)

data class EncapContentInfo(
    val eContentType: String,
    val eContent: EContent
)

data class EContent(
    val tstInfo: TSTInfo
)

data class TSTInfo(
    val version: Int,
    val policy: String,
    val messageImprint: MessageImprint,
    val serialNumber: String,
    val genTime: String,
    val accuracy: Accuracy?,
    val ordering: Boolean,
    val nonce: String?,
    val tsa: TSA?,
    val extensions: List<Extension>
)

data class Accuracy(
    val seconds: Int,
    val millis: Int,
    val micros: Int
)

data class TSA(
    val rdnSequence: List<RDN>
)

data class Certificate(
    val tbsCertificate: TBSCertificate,
    val signatureAlgorithm: HashAlgorithm,
    val signatureValue: String
)

data class TBSCertificate(
    val version: Int,
    val serialNumber: String,
    val signature: HashAlgorithm,
    val issuer: Issuer,
    val validity: Validity,
    val subject: Subject,
    val subjectPublicKeyInfo: SubjectPublicKeyInfo,
    val extensions: List<Extension>
)

data class Issuer(
    val rdnSequence: List<RDN>
)

data class Subject(
    val rdnSequence: List<RDN>
)

data class RDN(
    val type: String,
    val value: String
)

data class Validity(
    val notBefore: TimeValue,
    val notAfter: TimeValue
)

data class TimeValue(
    val generalTime: String
)

data class SubjectPublicKeyInfo(
    val algorithm: HashAlgorithm,
    val subjectPublicKey: String
)

data class SignerInfo(
    val version: Int,
    val sid: SID,
    val digestAlgorithm: HashAlgorithm,
    val signedAttrs: List<Attribute>,
    val signatureAlgorithm: HashAlgorithm,
    val signature: String,
    val unsignedAttrs: List<Any>
)

data class SID(
    val issuerAndSerialNumber: IssuerAndSerialNumber
)

data class IssuerAndSerialNumber(
    val issuer: Issuer,
    val serialNumber: String
)

data class Attribute(
    val attrType: String,
    val attrValues: List<Any>
)