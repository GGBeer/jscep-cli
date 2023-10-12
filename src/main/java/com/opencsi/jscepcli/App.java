package com.opencsi.jscepcli;

import java.io.IOException;
import java.net.URL;
import java.security.KeyPair;
import java.security.NoSuchAlgorithmException;
import java.security.Security;
import java.security.cert.CertStore;
import java.security.cert.CertStoreException;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.cert.X509CRL;
import java.security.cert.X509Certificate;
import java.security.interfaces.RSAPublicKey;
import java.util.Collection;

import javax.security.auth.callback.Callback;
import javax.security.auth.callback.CallbackHandler;
import javax.security.auth.callback.UnsupportedCallbackException;

import com.beust.jcommander.JCommander;
import com.beust.jcommander.ParameterException;
import org.bouncycastle.asn1.pkcs.Attribute;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.crypto.params.AsymmetricKeyParameter;
import org.bouncycastle.crypto.params.RSAKeyParameters;
import org.bouncycastle.crypto.util.PublicKeyFactory;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.pkcs.PKCS10CertificationRequest;
import org.jscep.client.CertificateVerificationCallback;
import org.jscep.client.Client;
import org.jscep.client.ClientException;
import org.jscep.client.EnrollmentResponse;
import org.jscep.transaction.OperationFailureException;
import org.jscep.transaction.TransactionException;
import org.jscep.util.CertificationRequestUtils;
import org.slf4j.LoggerFactory;


/**
 * @author asyd
 */
public class App {
    private static final org.slf4j.Logger logger = LoggerFactory.getLogger(App.class);

    private AppParameters params;
    private Client client;

    private App() {
    }

    public static void main(String[] args) throws Exception {
        System.setProperty("javax.net.debug", "none");

        logger.debug("main start");

        Security.addProvider(new BouncyCastleProvider());

        App app = new App();
        AppParameters params = new AppParameters();
        JCommander jcmd = new JCommander(params);
        jcmd.setColumnSize(120);

        try {
            jcmd.parse(args);

            app.setParams(params);
            if (params.getProxy() != null) {
                String[] proxy = params.getProxy().split(":", 2);
                System.setProperty("http.proxyHost", proxy[0]);
                if (proxy.length == 2) {
                    System.setProperty("http.proxyPort", proxy[1]);
                }
            }

            app.scepCLI();
        } catch (ParameterException e) {
            jcmd.usage();
        }
    }

    private void setParams(AppParameters params) {
        this.params = params;
        logger.debug("setParams: {}", params);
    }

    private void scepCLI() throws IOException, NoSuchAlgorithmException, CertificateException, OperatorCreationException {

        KeyPair csrKeyPair = getCsrKeyPair();
        String subjectDN = null;

        if (params.getDn() != null && !params.getDn().isEmpty()) {
            subjectDN = params.getDn();
        }

        PKCS10CertificationRequest certRequest = null;

        if (params.getCsrInputFile() != null) {
            certRequest = CertUtil.getPkcs10CertRequestFromFile(params.getCsrInputFile());
            boolean regenerateCReq = false;

            // Check PublicKey
            SubjectPublicKeyInfo pkInfo = certRequest.getSubjectPublicKeyInfo();
            AsymmetricKeyParameter keyParams = PublicKeyFactory.createKey(pkInfo);

            if (keyParams instanceof RSAKeyParameters rsaInputKeyParams) {
                if (!((RSAPublicKey) csrKeyPair.getPublic()).getPublicExponent().equals(rsaInputKeyParams.getExponent()) ||
                        !((RSAPublicKey) csrKeyPair.getPublic()).getModulus().equals(rsaInputKeyParams.getModulus())) {
                    logger.warn("InputFile CSR-PublicKey does not match with the current KeyPair. Will generate a new CSR using the current KeyPair and the InputFile CSR as input.");
                    regenerateCReq = true;
                }
            } else {
                // Ignore the KeyPair
                logger.warn("CertRequest InputFile contains an unsupported Key-Algorithm {}! Will generate a new CSR using the current KeyPair and the InputFile CSR as input.", keyParams.getClass().getSimpleName());
                regenerateCReq = true;
            }

            // Check ChallengePasswords
            String challenge = CertificationRequestUtils.getChallengePassword(certRequest);
            if(params.getChallenge()!=null && !(params.getChallenge().equals(challenge))) {
                logger.warn("InputFile CSR-ChallengePassword does not match with the provided ChallengePassword. Will generate a new CSR using the InputFile CSR and the provided ChallengePassword as input.");
                regenerateCReq = true;
                challenge = params.getChallenge();
            }

            // Check DN
            if(subjectDN==null){
                subjectDN = certRequest.getSubject().toString();
            }

            // TODO Check/add SAN-IP, SAN-FQDN, SAN-EMAIL püarams

            if(regenerateCReq) {
                certRequest = CertUtil.createCertificationRequest(csrKeyPair, subjectDN, certRequest, challenge,  params.getSigAlgorithm());
            }
        }

        X509Certificate cert = null;
        if (params.getCertInputFile() != null) {
            cert = CertUtil.getX509CertificateFromFile(params.getCertInputFile());
            if(subjectDN==null) {
                subjectDN = cert.getSubjectX500Principal().toString();
            }
        }

        if (subjectDN == null) {
            subjectDN = ""; // Empty DN!
        }

        if (cert == null) {
            cert = CertUtil.createSelfSignedCertificate(csrKeyPair, subjectDN, 7, params.getSigAlgorithm());
        }

        if (certRequest == null) {
            certRequest = CertUtil.createCertificationRequest(csrKeyPair, subjectDN, params.getChallenge(), params.getSigAlgorithm());
        }

        CertUtil.printPEM("PKCS#10 signing request", certRequest);
        if (params.getCsrOutputFile() != null) {
            CertUtil.saveToPEM(params.getCsrOutputFile(), certRequest);
        }

        CallbackHandler handler = new ConsoleCallbackHandler();
        URL serverURL = new URL(params.getUrl());

        try {
            logger.debug("Init SCEP-Client");
            this.client = new Client(serverURL, handler);

            Collection<? extends Certificate> caCertificates = getCaRaCertificates(params.getCaIdentifier());

            logger.debug("Starting enrollment certRequest for CA Identifier '{}'...", params.getCaIdentifier());
            EnrollmentResponse response = this.client.enrol(cert, csrKeyPair.getPrivate(), certRequest, params.getCaIdentifier());

            /*
             * handle asynchronous response
             */
            int pollingRetries = params.getPollingRetries();
            int pollingPeriod = params.getPollingPeriod();
            if (response.isPending()) {
                logger.debug("Enrollment certRequest returned CERT_REQ_PENDING, {} retries left", pollingRetries);
                do {
                    if (pollingRetries > 0) {
                        pollingRetries--;
                        logger.debug("Waiting {}s for next polling retry", pollingPeriod);
                        Thread.sleep(pollingPeriod * 1000L);

                        response = this.client.poll(cert, csrKeyPair.getPrivate(),
                                cert.getSubjectX500Principal(),
                                response.getTransactionId(),
                                params.getCaIdentifier());

                        if (response.isPending()) {
                            logger.debug("Polling certRequest returned CERT_REQ_PENDING, {} retries left", pollingRetries);
                        }
                    }

                } while (response.isPending() && pollingRetries > 0);
            }

            if (response.isSuccess()) {
                logger.debug("Enrollment certRequest successful!");

                X509Certificate clientCertificate = null;
                int certNum = 0;

                CertUtil.printPEM("RSA Private Key", csrKeyPair.getPrivate());
                if (params.getKeyOutputFile() != null) {
                    CertUtil.saveToPEM(params.getKeyOutputFile(), csrKeyPair.getPrivate());
                }

                CertStore store = response.getCertStore();
                Collection<? extends Certificate> certs = store.getCertificates(null);

                logger.debug("Received response containing {} certificate(s).", certs.size());

                for (Certificate value : certs) {
                    X509Certificate certificate = (X509Certificate) value;
                    certNum++;

                    /* Not an intermediate CA certificate */
                    clientCertificate = certificate;
                    CertUtil.printPEM("Certificate#" + certNum, certificate);
                    if (params.getEeCertificateOutputFile() != null) {
                        CertUtil.saveToPEM(params.getEeCertificateOutputFile(), certificate);
                    }
                }
                logger.debug("Certificate issued for subject DN: {}", clientCertificate.getSubjectDN().getName());

                if (logger.isTraceEnabled() || params.getCrlOutputFile() != null) {
                    X509CRL crl;

                    try {
                        crl = this.client.getRevocationList(clientCertificate,
                                csrKeyPair.getPrivate(),
                                clientCertificate.getIssuerX500Principal(),
                                clientCertificate.getSerialNumber(),
                                params.getCaIdentifier());

                        CertUtil.printPEM("Certificate Revocation List", crl);
                        CertUtil.saveToPEM(params.getCrlOutputFile(), crl);
                    } catch (OperationFailureException ofe) {
                        logger.error("Could not retrieve CRL: {}", ofe.getFailInfo());
                    }
                } else {
                    logger.debug("Skipping CRL output (neither a file nor --text was specified)");
                }

            } else if (response.isFailure()) {
                logger.error("Failure response: {}", response.getFailInfo());
            }
        } catch (ClientException e) {
            logger.error("Failure IOException: {}", e.getMessage());

            logger.error(e.getMessage());
            if (e.getMessage().contains("400")) {
                logger.error(". Probably a template issue, look at PKI log");
            } else if (e.getMessage().contains("404")) {
                logger.error(". Invalid URL or CA identifier");
            } else if (e.getMessage().contains("401")) {
                logger.error(". Probably EJBCA invalid entity status");
            }

        } catch (InterruptedException | CertStoreException | TransactionException e) {
            logger.error("Failure Exception: {}", e.getMessage());
        }
    }

    private KeyPair getCsrKeyPair() throws IOException, NoSuchAlgorithmException {
        KeyPair csrKeyPair;
        if (params.getKeyInputFile() != null) {
            csrKeyPair = CertUtil.getKeyPairFromFile(params.getKeyInputFile());
        } else {
            csrKeyPair = CertUtil.createRSAkeyPair(params.getKeySize());
        }
        return csrKeyPair;
    }

    private Collection<? extends Certificate> getCaRaCertificates(String caIdentifier) throws ClientException, CertStoreException {
        logger.debug("Getting CA certificates for CA Identifier '{}'...", caIdentifier);
        CertStore caCertificateStore = this.client.getCaCertificate(caIdentifier);
        Collection<? extends Certificate> caCertificates = caCertificateStore.getCertificates(null);
        int caCertificateNum = 0;

        if (caCertificates.isEmpty()) {
            logger.debug("No CA certificates received.");
        } else {
            logger.debug("Received {} CA certificate(s).", caCertificates.size());
        }

        for (Certificate caCcert : caCertificates) {
            caCertificateNum++;
            CertUtil.printPEM("CA Certificate#" + caCertificateNum, caCcert);
            if (params.getCaCertificateOutputFile() != null) {
                CertUtil.saveToPEM(params.getCaCertificateOutputFile(), caCcert);
            }
        }
        return caCertificates;
    }

    private static class ConsoleCallbackHandler implements CallbackHandler {

        @Override
        public void handle(Callback[] callbacks) throws UnsupportedCallbackException {
            for (Callback cb : callbacks) {
                if (cb instanceof CertificateVerificationCallback callback) {
                    callback.setVerified(true);
                } else {
                    throw new UnsupportedCallbackException(cb);
                }
            }
        }
    }

}
