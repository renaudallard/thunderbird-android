package com.fsck.k9.crypto.smime

import com.fsck.k9.mail.Body
import com.fsck.k9.mail.Multipart
import com.fsck.k9.mail.Part
import com.fsck.k9.mail.internet.MimeUtility

class SmimeEncryptionDetector {

    fun isEncrypted(part: Part): Boolean {
        return containsSmimeEncryptedPart(part)
    }

    private fun containsSmimeEncryptedPart(part: Part): Boolean {
        if (isSmimeEncryptedMimePart(part)) {
            return true
        }

        val body: Body = part.body ?: return false
        if (body is Multipart) {
            for (i in 0 until body.count) {
                if (containsSmimeEncryptedPart(body.getBodyPart(i))) {
                    return true
                }
            }
        }

        return false
    }

    private fun isSmimeEncryptedMimePart(part: Part): Boolean {
        if (!MimeUtility.isSameMimeType(part.mimeType, APPLICATION_PKCS7_MIME)) {
            return false
        }
        val smimeType = MimeUtility.getHeaderParameter(part.contentType, "smime-type")
        return "enveloped-data".equals(smimeType, ignoreCase = true) ||
            "authenveloped-data".equals(smimeType, ignoreCase = true) ||
            smimeType == null // missing smime-type on application/pkcs7-mime defaults to enveloped-data
    }

    companion object {
        private const val APPLICATION_PKCS7_MIME = "application/pkcs7-mime"
    }
}
