package com.opencsi.jscepcli;

import java.io.ByteArrayInputStream;
import java.io.FileInputStream;
import java.io.FileReader;
import java.io.FileWriter;
import java.io.IOException;
import java.io.InputStream;
import java.io.StringWriter;
import java.math.BigInteger;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.security.interfaces.RSAPrivateCrtKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.RSAPublicKeySpec;
import java.time.LocalDateTime;
import java.time.ZoneOffset;
import java.util.Date;

import javax.security.auth.x500.X500Principal;

import org.bouncycastle.asn1.DERPrintableString;
import org.bouncycastle.asn1.pkcs.Attribute;
import org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.X509v3CertificateBuilder;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.openssl.PEMKeyPair;
import org.bouncycastle.openssl.PEMParser;
import org.bouncycastle.openssl.jcajce.JcaPEMKeyConverter;
import org.bouncycastle.openssl.jcajce.JcaPEMWriter;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.bouncycastle.pkcs.PKCS10CertificationRequest;
import org.bouncycastle.pkcs.jcajce.JcaPKCS10CertificationRequestBuilder;
import org.slf4j.LoggerFactory;

/**
 *
 * @author asyd
 */
public class CertUtil {
    private static final org.slf4j.Logger logger = LoggerFactory.getLogger(CertUtil.class);

    private CertUtil()
    {
    }

    /**
     * This method creates a self signed certificate
     * @param kp KeyPair
     * @param dn DN-String
     * @param daysvalid validity
     * @return X509Certificate
     * @throws CertificateException
     * @throws OperatorCreationException
     * @throws IOException
     */
    public static X509Certificate createSelfSignedCertificate(KeyPair kp, String dn, int daysvalid, String sigAlgorithm) throws CertificateException, OperatorCreationException, IOException {
        LocalDateTime now = LocalDateTime.now();
        LocalDateTime validTo = now.plusDays(daysvalid);
        BigInteger serial = BigInteger.valueOf(now.toEpochSecond(ZoneOffset.UTC));

        X500Name principal = new X500Name(dn);
        SubjectPublicKeyInfo spki = SubjectPublicKeyInfo.getInstance(kp.getPublic().getEncoded());
        final X509v3CertificateBuilder certbuilder = new X509v3CertificateBuilder(principal, serial, Date.from(now.toInstant(ZoneOffset.UTC)), Date.from(validTo.toInstant(ZoneOffset.UTC)), principal, spki);
        final ContentSigner signer = new JcaContentSignerBuilder(sigAlgorithm).setProvider(new BouncyCastleProvider()).build(kp.getPrivate());
        final X509CertificateHolder certHolder = certbuilder.build(signer);
        return (X509Certificate) CertificateFactory.getInstance("X.509", new BouncyCastleProvider()).generateCertificate(new ByteArrayInputStream(certHolder.getEncoded()));      
    }

    public static PKCS10CertificationRequest createCertificationRequest(KeyPair kp, String dn, String password, String sigAlgorithm) {
        PKCS10CertificationRequest request = null;

        try {
            JcaPKCS10CertificationRequestBuilder builder = new JcaPKCS10CertificationRequestBuilder(new X500Principal(dn), kp.getPublic());

            if (password != null && !password.isEmpty()) {
                DERPrintableString passwordDer = new DERPrintableString(password);
                builder.setAttribute(PKCSObjectIdentifiers.pkcs_9_at_challengePassword, passwordDer);
            }

            JcaContentSignerBuilder signerBuilder = new JcaContentSignerBuilder(sigAlgorithm);
            request = builder.build(signerBuilder.build(kp.getPrivate()));
        } catch (OperatorCreationException e) {
            logger.error("Exception: {}", e.toString());
        }
        return request;
    }

    public static PKCS10CertificationRequest createCertificationRequest(KeyPair kp, String dn, PKCS10CertificationRequest request, String password, String sigAlgorithm) {

        try {
            JcaPKCS10CertificationRequestBuilder builder = new JcaPKCS10CertificationRequestBuilder(new X500Principal(dn), kp.getPublic());

            Attribute[] csrAttributes = request.getAttributes();
            for (Attribute attribute : csrAttributes) {

                if (PKCSObjectIdentifiers.pkcs_9_at_challengePassword.equals(attribute.getAttrType()) && password != null && !password.isEmpty()) {
                    // Replace ChallengePassword
                    DERPrintableString passwordDer = new DERPrintableString(password);
                    builder.addAttribute(PKCSObjectIdentifiers.pkcs_9_at_challengePassword, passwordDer);
                } else {
                    builder.addAttribute(attribute.getAttrType(), attribute.getAttributeValues());
                }
            }

            JcaContentSignerBuilder signerBuilder = new JcaContentSignerBuilder(sigAlgorithm);
            return builder.build(signerBuilder.build(kp.getPrivate()));
        } catch (OperatorCreationException e) {
            logger.error("Exception: {}", e.getMessage());
        }

        return null;
    }

    public static KeyPair createRSAkeyPair(Integer keySize) throws NoSuchAlgorithmException {
        logger.debug("Generating new RSA-{} KeyPair", keySize);
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("RSA");
        kpg.initialize(keySize);
        return kpg.genKeyPair();
    }

    public static void saveToPEM(String filename, Object data) {
        logger.debug("saveToPEM file: {}{}", filename, data==null ? " data=null!" : ".");
        if (filename == null || data==null) {
            return;
        }
        try (JcaPEMWriter writer = new JcaPEMWriter(new FileWriter(filename, true))) {
            writer.writeObject(data);
            writer.flush();
        } catch (IOException e) {
            logger.error("Could not save file: {}", filename);
            logger.error(e.getMessage());
        }
    }

    public static void printPEM(String title, Object data) {
        logger.trace("PrintPEM {}:{}", title, data==null ? " data=null!" : "");
        if (!logger.isTraceEnabled() || data==null) {
            return;
        }
        try (JcaPEMWriter writer = new JcaPEMWriter(new StringWriter())) {
            writer.writeObject(data);
            writer.flush();
            logger.trace("{}", writer);
        } catch (IOException e) {
            logger.error("Could not printPEM: {}", title);
            logger.error(e.getMessage());
        }
    }

    public static  X509Certificate getX509CertificateFromFile(String certInputFile) throws IOException, CertificateException {
        final X509Certificate cert;
        logger.debug("Reading existing certificate from '{}'", certInputFile);
        try (InputStream inStrm = new FileInputStream(certInputFile)) {
            final CertificateFactory cf = CertificateFactory.getInstance("X.509");
            cert = (X509Certificate) cf.generateCertificate(inStrm);
            logger.debug("Cert-Subject-DN: '{}'", cert.getSubjectX500Principal());
        }
        return cert;
    }

    public static PublicKey getRSAPublicKey(BigInteger modulus, BigInteger exponent) throws NoSuchAlgorithmException, InvalidKeySpecException {
        RSAPublicKeySpec rsaSpec = new RSAPublicKeySpec(modulus, exponent);
        KeyFactory kf = KeyFactory.getInstance("RSA");
        return kf.generatePublic(rsaSpec);
    }

    public static  PKCS10CertificationRequest getPkcs10CertRequestFromFile(String certReqFileName) throws IOException {
        PKCS10CertificationRequest pkcs10CertReq;
        // Read CSR
        logger.debug("Reading existing CSR from '{}'", certReqFileName);
        try (FileReader csrReader = new FileReader(certReqFileName)) {
            try (PEMParser pemParser = new PEMParser(csrReader)) {
                pkcs10CertReq = (PKCS10CertificationRequest) pemParser.readObject();
                logger.debug("CSR-Subject-DN: '{}'", pkcs10CertReq.getSubject());
                for (Attribute attribute : pkcs10CertReq.getAttributes()) {
                    logger.debug("CSR-Attribute: {}: {}", attribute.getAttrType().getId(), attribute.getAttrValues());
                }
            }
        }
        return pkcs10CertReq;
    }

    public static KeyPair getKeyPairFromFile(String keyFileName) throws IOException {
        KeyPair keyPair = null;
        logger.info("Reading existing private key from '{}'", keyFileName);
        try (FileReader keyReader = new FileReader(keyFileName)) {
            try (PEMParser pemParser = new PEMParser(keyReader)) {
                PEMKeyPair pemkey = (PEMKeyPair) pemParser.readObject();
                JcaPEMKeyConverter pemKeyConverter = new JcaPEMKeyConverter();
                PrivateKey privKey = pemKeyConverter.getPrivateKey(pemkey.getPrivateKeyInfo());
                logger.debug("PrivKey Algorithm: {}", privKey.getAlgorithm());
                PublicKey pubKey = pemKeyConverter.getPublicKey(pemkey.getPublicKeyInfo()); // KeyFile may optionally also include the PublicKey
                if (pubKey == null && privKey instanceof RSAPrivateCrtKey privk) {
                    pubKey = getRSAPublicKey(privk.getModulus(), privk.getPublicExponent()); // Derive RSA PubKey from PrivKey
                }
                keyPair = new KeyPair(pubKey, privKey);
            } catch (NoSuchAlgorithmException | InvalidKeySpecException e) {
                logger.error("Exception: {}", e.toString());
            }
        }
        return keyPair;
    }

}
