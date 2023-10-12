# Build

```bash
$ git clone git://github.com/asyd/jscep-cli-jdk6.git
$ cd jscep-cli
$ mvn compile
$ mvn package
$ java -jar target/jscepcli-1.2-jar-with-dependencies.jar
```

# Usage

```bash
$ java -jar target/jscepcli-1.3-SNAPSHOT-jar-with-dependencies.jar
Usage: <main class> [options]
  Options:
    --algorithm
      Signature algorithm to use (e.g. SHA256withRSA)
      Default: SHA256withRSA
    --ca-certificate-output-file
      CA certificate output file
      Default: cacert.pem
    --ca-identifier
      SCEP CA identifier (Note: The CA/RA may enforce restrictions/syntax to this identifier)
    --cert-input-file
      Pre created Certificate file for PKCSReq protection, instead of using a new generated self-signed
    --cert-key-input-file
      Private key file for PKCSReq protection, instead of using the CSR key (PEM format, requires matching --cert-input-file) 
    --challenge
      Challenge password (entity password)
    --crl-output-file
      CRL output file
      Default: crl.pem
    --csr-input-file
      Pre created CSR file (PEM format, requires matching --key-input-file)
    --csr-output-file
      CSR output file
      Default: csr.pem
    --dn
      Subject DN to request
    --ee-certificate-output-file
      EE certificate output file
      Default: cert.pem
    --fqdn
      Add SAN-FQDN to request
    --ipv4
      Add SAN-IPv4-Address to request
    --ipv6
      Add SAN-IPv6-Address to request
    --mail
      Add SAN-Email to request
    --key-input-file
      Pre created key file (PEM format) to be used for current CSR
    --key-output-file
      CSR Private key output file
      Default: privkey.pem
    --keysize
      Size of RSA key e.g. 1024, 2048, 3072, 4096, 8192 bits
      Default: 2048
    --polling-period
      Seconds to wait for next polling
      Default: 5
    --polling-retries
      Maximum number of polling retries
      Default: 0
    --proxy
      HTTP-Proxy, use <hostname>:<port>
    --ra-certificate-output-file
      RA certificate output file
      Default: racert.pem
  * --url
      SCEP URL. For example, http://<hostname>:<port>/caservices/scep/pkiclient.exe
```
