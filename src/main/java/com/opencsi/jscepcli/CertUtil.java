/*
 * To change this template, choose Tools | Templates
 * and open the template in the editor.
 */
package com.opencsi.jscepcli;

import java.math.BigInteger;
import java.security.KeyPair;
import java.security.cert.X509Certificate;
import java.util.Date;
import javax.security.auth.x500.X500Principal;
import javax.xml.bind.DatatypeConverter;

import org.bouncycastle.asn1.DERPrintableString;
import org.bouncycastle.asn1.pkcs.Attribute;
import org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers;
import org.bouncycastle.cert.X509v3CertificateBuilder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.pkcs.PKCS10CertificationRequest;
import org.bouncycastle.pkcs.jcajce.JcaPKCS10CertificationRequestBuilder;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;


/**
 * @author asyd
 */
class CertUtil {

    /*
     * @description This method create a self signed certificated
     */
    X509Certificate createSelfSignedCertificate(KeyPair kp, String dn) throws Exception {
        Date now = new Date();
        BigInteger serial = new BigInteger("1");

        X509v3CertificateBuilder certificateBuilder = new JcaX509v3CertificateBuilder(
                parseDN(dn),
                serial,
                now,
                now,
                parseDN(dn),
                kp.getPublic()
        );

        ContentSigner contentSigner = new JcaContentSignerBuilder(Constants.algorithm).build(kp.getPrivate());

        return new JcaX509CertificateConverter()
                .setProvider(
                        BouncyCastleProvider.PROVIDER_NAME).
                        getCertificate(certificateBuilder.build(contentSigner)
                        );
    }


    PKCS10CertificationRequest createCertificationRequest(KeyPair kp, String dn, String password) {
        PKCS10CertificationRequest request;

        try {
            JcaPKCS10CertificationRequestBuilder builder = new JcaPKCS10CertificationRequestBuilder(new X500Principal(dn), kp.getPublic());

            if (password!=null) {
                DERPrintableString passwordDer = new DERPrintableString(password);
                builder.addAttribute(PKCSObjectIdentifiers.pkcs_9_at_challengePassword, passwordDer);
            }
            
            JcaContentSignerBuilder signerBuilder = new JcaContentSignerBuilder(Constants.algorithm);
            request = builder.build(signerBuilder.build(kp.getPrivate()));
        } catch (Exception e) {
            e.printStackTrace();
            return null;
        }
        return request;
    }


    PKCS10CertificationRequest createCertificationRequest(KeyPair kp, PKCS10CertificationRequest request, String password) {
        try {
            JcaPKCS10CertificationRequestBuilder builder = new JcaPKCS10CertificationRequestBuilder(
                    request.getSubject(), kp.getPublic()
            );

            Attribute[] csrAttributes = request.getAttributes();
            for (Attribute a : csrAttributes) {
                builder.addAttribute(a.getAttrType(), a.getAttributeValues());
            }

            if (password != null) {
                DERPrintableString passwordDer = new DERPrintableString(password);
                builder.addAttribute(PKCSObjectIdentifiers.pkcs_9_at_challengePassword, passwordDer);
            }

            JcaContentSignerBuilder signerBuilder = new JcaContentSignerBuilder(Constants.algorithm);
            request = builder.build(signerBuilder.build(kp.getPrivate()));
        } catch (Exception e) {
            e.printStackTrace();
            return null;
        }
        return request;
    }


    private X500Principal parseDN(String dn) {
        return new X500Principal(dn);
    }


    static byte[] parseDERfromPEM(byte[] pem, String beginDelimiter, String endDelimiter)
            throws ArrayIndexOutOfBoundsException, NullPointerException {
        String data = new String(pem);
        String[] tokens = data.split(beginDelimiter);
        try {
            tokens = tokens[1].split(endDelimiter);
            return DatatypeConverter.parseBase64Binary(tokens[0]);
        } catch (ArrayIndexOutOfBoundsException e) {
            return pem;
        }
    }

}
