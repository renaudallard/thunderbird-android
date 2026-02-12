package com.fsck.k9.crypto.smime

import java.security.cert.X509Certificate
import java.util.Date
import net.thunderbird.core.logging.legacy.Log
import org.bouncycastle.cert.X509CertificateHolder
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter
import org.bouncycastle.cms.CMSProcessableByteArray
import org.bouncycastle.cms.CMSSignedData
import org.bouncycastle.cms.SignerInformation
import org.bouncycastle.cms.jcajce.JcaSimpleSignerInfoVerifierBuilder
import org.bouncycastle.util.Store

class SmimeSignatureVerifier {

    fun verifyDetachedSignature(
        signedData: ByteArray,
        signatureData: ByteArray,
    ): SmimeSignatureResult {
        return try {
            verifyInternal(signedData, signatureData)
        } catch (e: Exception) {
            Log.e(e, "Error verifying S/MIME signature")
            SmimeSignatureResult(
                isValid = false,
                error = SmimeSignatureError.PARSE_ERROR,
            )
        }
    }

    private fun verifyInternal(
        signedData: ByteArray,
        signatureData: ByteArray,
    ): SmimeSignatureResult {
        val content = CMSProcessableByteArray(signedData)
        val cmsSignedData = CMSSignedData(content, signatureData)

        val signerInfo = cmsSignedData.signerInfos.signers.firstOrNull()
            ?: return SmimeSignatureResult(
                isValid = false,
                error = SmimeSignatureError.MISSING_CERTIFICATE,
            )

        val certStore: Store<X509CertificateHolder> = cmsSignedData.certificates
        val certHolder = findSignerCertificate(signerInfo, certStore)
            ?: return SmimeSignatureResult(
                isValid = false,
                error = SmimeSignatureError.MISSING_CERTIFICATE,
            )

        val signerCert = JcaX509CertificateConverter().getCertificate(certHolder)
        val signerEmail = extractEmail(signerCert)

        // Check certificate validity
        val now = Date()
        if (now.after(signerCert.notAfter) || now.before(signerCert.notBefore)) {
            return SmimeSignatureResult(
                isValid = false,
                signerCertificate = signerCert,
                signerEmail = signerEmail,
                error = SmimeSignatureError.EXPIRED_CERTIFICATE,
            )
        }

        // Verify signature
        val verifier = JcaSimpleSignerInfoVerifierBuilder().build(signerCert)
        val isValid = signerInfo.verify(verifier)

        return if (isValid) {
            SmimeSignatureResult(
                isValid = true,
                signerCertificate = signerCert,
                signerEmail = signerEmail,
            )
        } else {
            SmimeSignatureResult(
                isValid = false,
                signerCertificate = signerCert,
                signerEmail = signerEmail,
                error = SmimeSignatureError.INVALID_SIGNATURE,
            )
        }
    }

    private fun findSignerCertificate(
        signerInfo: SignerInformation,
        certStore: Store<X509CertificateHolder>,
    ): X509CertificateHolder? {
        val sid = signerInfo.sid
        val allCerts = certStore.getMatches(null)
        return allCerts.filterIsInstance<X509CertificateHolder>().firstOrNull { cert ->
            cert.serialNumber == sid.serialNumber && cert.issuer == sid.issuer
        }
    }

    private fun extractEmail(cert: X509Certificate): String? {
        val subjectDN = cert.subjectX500Principal.name
        val emailPattern = Regex("EMAILADDRESS=([^,]+)|E=([^,]+)")
        val match = emailPattern.find(subjectDN)
        if (match != null) {
            return match.groupValues[1].ifEmpty { match.groupValues[2] }
        }

        // Check Subject Alternative Names (RFC822Name = type 1)
        val sanList = cert.subjectAlternativeNames ?: return null
        for (san in sanList) {
            if (san.size >= 2 && san[0] == 1) {
                return san[1] as? String
            }
        }

        return null
    }
}
