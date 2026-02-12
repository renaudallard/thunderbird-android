package com.fsck.k9.crypto.smime

import com.fsck.k9.crypto.EncryptionExtractor
import com.fsck.k9.crypto.EncryptionResult
import com.fsck.k9.mail.Message

class SmimeEncryptionExtractor internal constructor(
    private val encryptionDetector: SmimeEncryptionDetector,
) : EncryptionExtractor {

    override fun extractEncryption(message: Message): EncryptionResult? {
        return if (encryptionDetector.isEncrypted(message)) {
            EncryptionResult(ENCRYPTION_TYPE, 0)
        } else {
            null
        }
    }

    companion object {
        const val ENCRYPTION_TYPE = "smime"

        @JvmStatic
        fun newInstance(): SmimeEncryptionExtractor {
            val encryptionDetector = SmimeEncryptionDetector()
            return SmimeEncryptionExtractor(encryptionDetector)
        }
    }
}
