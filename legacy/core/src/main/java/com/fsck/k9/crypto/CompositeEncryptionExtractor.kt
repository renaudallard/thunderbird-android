package com.fsck.k9.crypto

import com.fsck.k9.mail.Message

class CompositeEncryptionExtractor(
    private val extractors: List<EncryptionExtractor>,
) : EncryptionExtractor {
    override fun extractEncryption(message: Message): EncryptionResult? {
        return extractors.firstNotNullOfOrNull { it.extractEncryption(message) }
    }
}
