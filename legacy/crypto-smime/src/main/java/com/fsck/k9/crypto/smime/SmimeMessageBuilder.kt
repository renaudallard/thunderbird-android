package com.fsck.k9.crypto.smime

import android.content.Context
import android.content.Intent
import android.security.KeyChain
import com.fsck.k9.CoreResourceProvider
import com.fsck.k9.mail.BoundaryGenerator
import com.fsck.k9.mail.internet.BinaryTempFileBody
import com.fsck.k9.mail.internet.MessageIdGenerator
import com.fsck.k9.mail.internet.MimeBodyPart
import com.fsck.k9.mail.internet.MimeMessage
import com.fsck.k9.mail.internet.MimeMultipart
import com.fsck.k9.message.CryptoStatus
import com.fsck.k9.message.MessageBuilder
import java.io.ByteArrayOutputStream
import net.thunderbird.core.common.exception.MessagingException
import net.thunderbird.core.logging.legacy.Log
import net.thunderbird.core.preference.GeneralSettingsManager

class SmimeMessageBuilder(
    messageIdGenerator: MessageIdGenerator,
    boundaryGenerator: BoundaryGenerator,
    resourceProvider: CoreResourceProvider,
    settingsManager: GeneralSettingsManager,
    private val context: Context,
) : MessageBuilder(messageIdGenerator, boundaryGenerator, resourceProvider, settingsManager) {

    private var cryptoStatus: CryptoStatus? = null

    fun setCryptoStatus(cryptoStatus: CryptoStatus) {
        this.cryptoStatus = cryptoStatus
    }

    override fun buildMessageInternal() {
        try {
            val message = build()
            val status = cryptoStatus

            if (status == null || !status.isSmimeSigningEnabled || status.smimeCertificateAlias == null) {
                queueMessageBuildSuccess(message)
                return
            }

            if (isDraft) {
                queueMessageBuildSuccess(message)
                return
            }

            val signedMessage = signMessage(message, status.smimeCertificateAlias!!)
            queueMessageBuildSuccess(signedMessage)
        } catch (e: MessagingException) {
            queueMessageBuildException(e)
        } catch (e: Exception) {
            Log.e(e, "Error signing S/MIME message")
            queueMessageBuildException(MessagingException("Error signing S/MIME message", e))
        }
    }

    private fun signMessage(message: MimeMessage, certAlias: String): MimeMessage {
        val privateKey = KeyChain.getPrivateKey(context, certAlias)
            ?: throw MessagingException("Could not retrieve private key for alias: $certAlias")
        val certChain = KeyChain.getCertificateChain(context, certAlias)
            ?: throw MessagingException("Could not retrieve certificate chain for alias: $certAlias")

        val cmsOps = SmimeCmsOperations()

        // Serialize the body part to CRLF-canonicalized bytes
        val bodyBytes = ByteArrayOutputStream().use { bos ->
            message.writeTo(bos)
            bos.toByteArray()
        }

        val signatureBytes = cmsOps.createDetachedSignature(bodyBytes, privateKey, certChain)
        val micAlgorithm = cmsOps.getMicAlgorithm(signatureBytes)

        // Build multipart/signed
        val boundary = BoundaryGenerator.getInstance().generateBoundary()
        val multipartSigned = MimeMultipart(boundary)
        multipartSigned.setSubType("signed; protocol=\"application/pkcs7-signature\"; micalg=$micAlgorithm")

        // Original message body becomes first part
        val bodyPart = MimeBodyPart(message.body, message.contentType)
        multipartSigned.addBodyPart(bodyPart)

        // Signature becomes second part
        val signatureBody = BinaryTempFileBody("application/pkcs7-signature")
        signatureBody.outputStream.use { os ->
            os.write(signatureBytes)
        }
        val signaturePart = MimeBodyPart(signatureBody, "application/pkcs7-signature; name=\"smime.p7s\"")
        signaturePart.setHeader("Content-Disposition", "attachment; filename=\"smime.p7s\"")
        signaturePart.setHeader("Content-Transfer-Encoding", "base64")
        multipartSigned.addBodyPart(signaturePart)

        // Replace message body
        message.setBody(multipartSigned)
        message.setHeader(
            "Content-Type",
            "multipart/signed; protocol=\"application/pkcs7-signature\";" +
                " micalg=$micAlgorithm; boundary=\"$boundary\"",
        )

        return message
    }

    override fun buildMessageOnActivityResult(requestCode: Int, data: Intent?) {
        throw UnsupportedOperationException()
    }

    companion object {
        @JvmStatic
        fun newInstance(context: Context): SmimeMessageBuilder {
            return SmimeMessageBuilder(
                MessageIdGenerator.getInstance(),
                BoundaryGenerator.getInstance(),
                app.k9mail.legacy.di.DI.get(CoreResourceProvider::class.java),
                app.k9mail.legacy.di.DI.get(GeneralSettingsManager::class.java),
                context,
            )
        }
    }
}
