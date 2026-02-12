package com.fsck.k9.crypto.smime

import java.security.cert.X509Certificate

data class SmimeSignatureResult(
    val isValid: Boolean,
    val signerCertificate: X509Certificate? = null,
    val signerEmail: String? = null,
    val error: SmimeSignatureError? = null,
)

enum class SmimeSignatureError {
    INVALID_SIGNATURE,
    EXPIRED_CERTIFICATE,
    MISSING_CERTIFICATE,
    PARSE_ERROR,
}
