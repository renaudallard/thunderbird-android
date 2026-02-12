package com.fsck.k9.crypto.smime

import java.security.PrivateKey
import java.security.cert.X509Certificate
import org.bouncycastle.asn1.ASN1ObjectIdentifier
import org.bouncycastle.asn1.nist.NISTObjectIdentifiers
import org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers
import org.bouncycastle.cert.jcajce.JcaCertStore
import org.bouncycastle.cms.CMSProcessableByteArray
import org.bouncycastle.cms.CMSSignedData
import org.bouncycastle.cms.CMSSignedDataGenerator
import org.bouncycastle.cms.jcajce.JcaSignerInfoGeneratorBuilder
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder
import org.bouncycastle.operator.jcajce.JcaDigestCalculatorProviderBuilder

class SmimeCmsOperations {

    fun createDetachedSignature(
        bodyBytes: ByteArray,
        privateKey: PrivateKey,
        certChain: Array<X509Certificate>,
    ): ByteArray {
        val signingCert = certChain.first()
        val signatureAlgorithm = getSignatureAlgorithm(signingCert)

        val contentSigner = JcaContentSignerBuilder(signatureAlgorithm).build(privateKey)
        val digestProvider = JcaDigestCalculatorProviderBuilder().build()
        val signerInfoGenerator = JcaSignerInfoGeneratorBuilder(digestProvider).build(contentSigner, signingCert)

        val certStore = JcaCertStore(certChain.toList())

        val generator = CMSSignedDataGenerator()
        generator.addSignerInfoGenerator(signerInfoGenerator)
        generator.addCertificates(certStore)

        val content = CMSProcessableByteArray(bodyBytes)
        val signedData = generator.generate(content, false)

        return signedData.encoded
    }

    fun getMicAlgorithm(signatureBytes: ByteArray): String {
        val signedData = CMSSignedData(signatureBytes)
        val signerInfo = signedData.signerInfos.signers.firstOrNull()
            ?: return DEFAULT_MIC_ALGORITHM

        val digestOid = signerInfo.digestAlgOID
        return micAlgorithmFromOid(ASN1ObjectIdentifier(digestOid)) ?: DEFAULT_MIC_ALGORITHM
    }

    fun getSignatureAlgorithm(cert: X509Certificate): String {
        return when (cert.publicKey.algorithm) {
            "RSA" -> "SHA256WithRSA"
            "EC", "ECDSA" -> "SHA256WithECDSA"
            "Ed25519" -> "Ed25519"
            "Ed448" -> "Ed448"
            else -> "SHA256WithRSA"
        }
    }

    companion object {
        private const val DEFAULT_MIC_ALGORITHM = "sha-256"

        private fun micAlgorithmFromOid(oid: ASN1ObjectIdentifier): String? {
            return when (oid) {
                NISTObjectIdentifiers.id_sha256 -> "sha-256"
                NISTObjectIdentifiers.id_sha384 -> "sha-384"
                NISTObjectIdentifiers.id_sha512 -> "sha-512"
                PKCSObjectIdentifiers.md5 -> "md5"
                else -> null
            }
        }
    }
}
