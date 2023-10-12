/*
 * To change this template, choose Tools | Templates
 * and open the template in the editor.
 */
package com.opencsi.jscepcli;

import com.beust.jcommander.Parameter;
import com.beust.jcommander.validators.PositiveInteger;

/**
 * @author asyd
 */
public class AppParameters {

    @Parameter(names = "--keysize", description = "Size of RSA key e.g. 1024, 2048, 3072, 4096, 8192 bits")
    private Integer keySize = 2048;
    @Parameter(names = "--algorithm", description = "Signature algorithm to use (e.g. SHA256withRSA)")
    private String sigAlgorithm = "SHA256withRSA";

    @Parameter(names = "--dn", description = "Subject DN to request")
    private String dn = null;
    @Parameter(names = "--ipv4", description = "Add SAN-IPv4-Address to request")
    private String ipv4 = null;
    @Parameter(names = "--ipv6", description = "Add SAN-IPv6-Address to request")
    private String ipv6 = null;
    @Parameter(names = "--fqdn", description = "Add SAN-FQDN to request")
    private String fqdn = null;
    @Parameter(names = "--mail", description = "Add SAN-Email to request")
    private String email = null;
    @Parameter(names = "--challenge", description = "Challenge password (entity password)")
    private String challenge = null;

    @Parameter(names = "--ca-identifier", description = "SCEP CA identifier (Note: The CA/RA may enforce restrictions/syntax to this identifier)")
    private String caIdentifier = null;

    @Parameter(names = "--url", description = "SCEP URL. For example, http://<hostname>:<port>/caservices/scep/pkiclient.exe", required = true)
    private String url = null;
    @Parameter(names = "--proxy", description = "HTTP-Proxy, use <hostname>:<port>")
    private String proxy = null;
    @Parameter(names = "--polling-period", description = "Seconds to wait for next polling", validateWith = {PositiveInteger.class})
    private Integer pollingPeriod = 5;
    @Parameter(names = "--polling-retries", description = "Maximum number of polling retries", validateWith = {PositiveInteger.class})
    private Integer pollingRetries = 0;

    @Parameter(names = "--key-input-file", description = "Pre created key file (PEM format) to be used for current CSR")
    private String keyInputFile = null;
    @Parameter(names = "--csr-input-file", description = "Pre created CSR file (PEM format, requires matching --key-input-file)")
    private String csrInputFile = null;
    @Parameter(names = "--cert-input-file", description = "Pre created Certificate file for PKCSReq protection, instead of using a new generated self-signed")
    private String certInputFile = null;
    @Parameter(names = "--cert-key-input-file", description = "Private key file for PKCSReq protection, instead of using the CSR key (PEM format, requires matching --cert-input-file)")
    private String certKeyInputFile = null;

    @Parameter(names = "--key-output-file", description = "CSR Private key output file")
    private String keyOutputFile = "privkey.pem";
    @Parameter(names = "--csr-output-file", description = "CSR output file")
    private String csrOutputFile = "csr.pem";
    @Parameter(names = "--ee-certificate-output-file", description = "EE certificate output file")
    private String eeCertificateOutputFile = "cert.pem";
    @Parameter(names = "--ca-certificate-output-file", description = "CA certificate output file")
    private String caCertificateOutputFile = "cacert.pem";
    @Parameter(names = "--ra-certificate-output-file", description = "RA certificate output file")
    private String raCertificateOutputFile = "racert.pem";
    @Parameter(names = "--crl-output-file", description = "CRL output file")
    private String crlOutputFile = "crl.pem";

    /**
     *
     * @return KeySize
     */
    public Integer getKeySize() {
        return keySize;
    }

    /**
     *
     * @return SigAlgorithm
     */
    public String getSigAlgorithm() {
        return sigAlgorithm;
    }

    /**
     *
     * @return DN
     */
    public String getDn() {
        return dn;
    }

    /**
     *
     * @return IPv4
     */
    public String getIpv4() {
        return ipv4;
    }

    /**
     *
     * @return IPv6
     */
    public String getIpv6() {
        return ipv6;
    }

    /**
     *
     * @return FQDN
     */
    public String getFqdn() {
        return fqdn;
    }

    /**
     *
     * @return Email
     */
    public String getEmail() {
        return email;
    }

    /**
     *
     * @return Challenge
     */
    public String getChallenge() {
        return challenge;
    }

    /**
     *
     * @return CaIdentifier
     */
    public String getCaIdentifier() {
        return caIdentifier;
    }

    /**
     *
     * @return URL
     */
    public String getUrl() {
        return url;
    }

    /**
     *
     * @return Proxy
     */
    public String getProxy() {
        return proxy;
    }

    /**
     *
     * @return PollingPeriod
     */
    public Integer getPollingPeriod() {
        return pollingPeriod;
    }

    /**
     *
     * @return PollingRetries
     */
    public Integer getPollingRetries() {
        return pollingRetries;
    }

    /**
     *
     * @return KeyInputFile
     */
    public String getKeyInputFile() {
        return keyInputFile;
    }

    /**
     *
     * @return CsrInputFile
     */
    public String getCsrInputFile() {
        return csrInputFile;
    }

    /**
     *
     * @return CertInputFile
     */
    public String getCertInputFile() {
        return certInputFile;
    }

    /**
     *
     * @return CertKeyInputFile
     */
    public String getCertKeyInputFile() {
        return certKeyInputFile;
    }

    /**
     *
     * @return KeyOutputFile
     */
    public String getKeyOutputFile() {
        return keyOutputFile;
    }

    /**
     *
     * @return CsrOutputFile
     */
    public String getCsrOutputFile() {
        return csrOutputFile;
    }

    /**
     *
     * @return EeCertificateOutputFile
     */
    public String getEeCertificateOutputFile() {
        return eeCertificateOutputFile;
    }

    /**
     *
     * @return CaCertificateOutputFile
     */
    public String getCaCertificateOutputFile() {
        return caCertificateOutputFile;
    }

    /**
     *
     * @return RaCertificateOutputFile
     */
    public String getRaCertificateOutputFile() {
        return raCertificateOutputFile;
    }

    /**
     *
     * @return CrlOutputFile
     */
    public String getCrlOutputFile() {
        return crlOutputFile;
    }

    @Override
    public String toString() {
        return "AppParameters{" +
                "keySize=" + keySize +
                ", sigAlgorithm='" + sigAlgorithm + '\'' +
                ", dn='" + dn + '\'' +
                ", ipv4='" + ipv4 + '\'' +
                ", ipv6='" + ipv6 + '\'' +
                ", fqdn='" + fqdn + '\'' +
                ", email='" + email + '\'' +
                ", challenge='" + challenge + '\'' +
                ", caIdentifier='" + caIdentifier + '\'' +
                ", url='" + url + '\'' +
                ", proxy='" + proxy + '\'' +
                ", pollingPeriod=" + pollingPeriod +
                ", pollingRetries=" + pollingRetries +
                ", keyInputFile='" + keyInputFile + '\'' +
                ", csrInputFile='" + csrInputFile + '\'' +
                ", certInputFile='" + certInputFile + '\'' +
                ", certKeyInputFile='" + certKeyInputFile + '\'' +
                ", keyOutputFile='" + keyOutputFile + '\'' +
                ", csrOutputFile='" + csrOutputFile + '\'' +
                ", eeCertificateOutputFile='" + eeCertificateOutputFile + '\'' +
                ", caCertificateOutputFile='" + caCertificateOutputFile + '\'' +
                ", raCertificateOutputFile='" + raCertificateOutputFile + '\'' +
                ", crlOutputFile='" + crlOutputFile + '\'' +
                '}';
    }
}
