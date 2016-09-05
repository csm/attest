(ns attest.core
  (:require [clojure.java.io :refer [reader writer]])
  (:import [java.security KeyPairGenerator PrivateKey KeyPair Security MessageDigest]
           [org.bouncycastle.asn1.x500 X500Name]
           [java.util Calendar Date Base64 Vector]
           [org.bouncycastle.asn1.x509 SubjectPublicKeyInfo Extension KeyUsage BasicConstraints ExtendedKeyUsage KeyPurposeId SubjectKeyIdentifier AuthorityKeyIdentifier]
           [org.bouncycastle.cert X509v3CertificateBuilder]
           [org.bouncycastle.operator.jcajce JcaContentSignerBuilder]
           [org.bouncycastle.cert.jcajce JcaX509CertificateConverter JcaX500NameUtil JcaX509ExtensionUtils]
           [sun.security.provider X509Factory]
           [java.security.cert X509Certificate]
           [org.bouncycastle.openssl PEMParser]
           [org.bouncycastle.pkcs PKCS10CertificationRequest PKCS10CertificationRequestBuilder PKCS8EncryptedPrivateKeyInfo]
           [org.bouncycastle.openssl.jcajce JceOpenSSLPKCS8EncryptorBuilder JcaPKCS8Generator JceOpenSSLPKCS8DecryptorProviderBuilder JcaPEMKeyConverter]
           [org.bouncycastle.util.io.pem PemWriter]
           [org.bouncycastle.jce.provider BouncyCastleProvider])
  (:gen-class))

(defn init!
  []
  ;(println (not-any? #(instance? BouncyCastleProvider %) (Security/getProviders)))
  (when (not-any? #(instance? BouncyCastleProvider %) (Security/getProviders))
    ;(println "Installing BouncyCastleProvider...")
    (Security/addProvider (BouncyCastleProvider.))))

(defn write-cert
  "Write cert to destination, PEM-formatted. Destination should be openable by clojure.java.io/writer."
  [^X509Certificate cert destination]
  (with-open [writer (writer destination)]
    (.write writer (str X509Factory/BEGIN_CERT \newline))
    (doall (for [line (map #(apply str (concat % [\newline]))
                           (partition 72 72 [] (.encodeToString (Base64/getEncoder) (.getEncoded cert))))]
             (.write writer line)))
    (.write writer (str X509Factory/END_CERT \newline))))

(defn read-cert
  "Read a PEM-formatted cert from source. Source should be openable by clojure.java.io/reader."
  [source]
  (with-open [reader (PEMParser. (reader source))]
    (.getCertificate (JcaX509CertificateConverter.)
                     (.readObject reader))))

(defn write-csr
  [^PKCS10CertificationRequest csr destination]
  (with-open [writer (writer destination)]
    (.write writer "-----BEGIN CERTIFICATE REQUEST-----\n")
    (doall (for [line (map #(apply str (concat % [\newline]))
                           (partition 72 72 [] (.encodeToString (Base64/getEncoder) (.getEncoded csr))))]
             (.write writer line)))
    (.write writer "-----END CERTIFICATE REQUEST-----\n")))

(defn read-csr
  [source]
  (with-open [reader (PEMParser. (reader source))]
    (let [request (.readObject reader)]
      (if (instance? PKCS10CertificationRequest request)
        request
        (throw (IllegalArgumentException. "not a valid certificate signing request"))))))

(defn write-private-key
  [key password destination]
  (let [encryptor (-> (JceOpenSSLPKCS8EncryptorBuilder. JcaPKCS8Generator/AES_128_CBC)
                      (.setPasssword password)
                      (.build))
        generator (JcaPKCS8Generator. key encryptor)
        pem-key (.generate generator)]
    (with-open [writer (PemWriter. (writer destination))]
      (.writeObject writer pem-key))))

(defn read-private-key
  [source password]
  (let [epki (with-open [reader (PEMParser. (reader source))]
               (let [res (.readObject reader)]
                 (if (instance? PKCS8EncryptedPrivateKeyInfo res)
                   res
                   (throw (IllegalArgumentException. "not a valid PKCS8 encrypted private key")))))
        decryptor (.build (JceOpenSSLPKCS8DecryptorProviderBuilder.) password)
        pki (.decryptPrivateKeyInfo epki decryptor)]
    (.getPrivateKey (JcaPEMKeyConverter.) pki)))

(defn generate-key-pair
  "Generate a new key pair."
  [& {:keys [alg key-length] :or {alg "RSA" key-length 2048}}]
  (.generateKeyPair (doto (KeyPairGenerator/getInstance alg) (.initialize key-length))))

(defn generate-csr
  "Generate a certificate signing request."
  [name key-pair
   & {:keys [alg hash-alg]
      :or {alg "RSA" hash-alg "SHA256"}}]
  (let [subject (X500Name. name)
        spki (SubjectPublicKeyInfo/getInstance (.getEncoded (.getPublic key-pair)))
        builder (PKCS10CertificationRequestBuilder. subject spki)
        signer (.build
                 (JcaContentSignerBuilder. (str hash-alg "with" alg))
                 (.getPrivate key-pair))]
      (.build builder signer)))

(defn generate-root-cert
  "Generates a new self-signed root certificate."
  [^KeyPair key-pair & {:keys [hash-alg ^String name years]
                        :or {hash-alg "SHA256" name "CN=CA" years 20}}]
  (let [subject (X500Name. name)
        expires (doto (Calendar/getInstance) (.add Calendar/YEAR years))
        spki (SubjectPublicKeyInfo/getInstance (.getEncoded (.getPublic key-pair)))
        builder (doto
                  (X509v3CertificateBuilder. subject
                                             (biginteger 1N)
                                             (Date.)
                                             (.getTime expires)
                                             subject
                                             spki)
                  (.addExtension Extension/keyUsage true (KeyUsage. (bit-or KeyUsage/keyCertSign KeyUsage/cRLSign)))
                  (.addExtension Extension/basicConstraints true (BasicConstraints. true))
                  (.addExtension Extension/subjectKeyIdentifier false
                                 (.createSubjectKeyIdentifier (JcaX509ExtensionUtils.) spki)))
        signer (.build
                 (JcaContentSignerBuilder. (str hash-alg "withRSA"))
                 (.getPrivate key-pair))
        certificate (.build builder signer)]
    (.getCertificate (JcaX509CertificateConverter.) certificate)))

(defn generate-ca-cert
  "Generate a new CA certificate."
  [^X509Certificate cert ^PrivateKey private-key ^PKCS10CertificationRequest csr serial-number
   & {:keys [hash-alg years ^int max-path-length] :or {hash-alg "SHA256" years 1 max-path-length 5}}]
  (let [expires (doto (Calendar/getInstance) (.add Calendar/YEAR years))
        builder (doto
                  (X509v3CertificateBuilder. (X500Name. (str (.getSubjectX500Principal cert)))
                                             (biginteger serial-number)
                                             (Date.)
                                             (.getTime expires)
                                             (.getSubject csr)
                                             (.getSubjectPublicKeyInfo csr))
                  (.addExtension Extension/keyUsage true (KeyUsage. (bit-or KeyUsage/keyCertSign KeyUsage/cRLSign)))
                  (.addExtension Extension/basicConstraints true
                                 (if max-path-length
                                     (BasicConstraints. max-path-length)
                                     (BasicConstraints. true)))
                  (.addExtension Extension/subjectKeyIdentifier false
                                 (.createSubjectKeyIdentifier (JcaX509ExtensionUtils.)
                                                              (.getSubjectPublicKeyInfo csr)))
                  (.addExtension Extension/authorityKeyIdentifier false
                                 (.createAuthorityKeyIdentifier (JcaX509ExtensionUtils.) cert)))
        signer (.build
                 (JcaContentSignerBuilder. (str hash-alg "withRSA"))
                 private-key)
        certificate (.build builder signer)]
    (.getCertificate (JcaX509CertificateConverter.) certificate)))

(defn generate-user-cert
  "Generate an end-user cert, for server or client TLS auth."
  [^X509Certificate cert ^PrivateKey private-key ^PKCS10CertificationRequest csr serial-number
   & {:keys [hash-alg years] :or {hash-alg "SHA256" years 1}}]
  (let [expires (doto (Calendar/getInstance) (.add Calendar/YEAR years))
        builder (doto
                  (X509v3CertificateBuilder. (JcaX500NameUtil/getSubject cert)
                                             (biginteger serial-number)
                                             (Date.)
                                             (.getTime expires)
                                             (.getSubject csr)
                                             (.getSubjectPublicKeyInfo csr))
                  (.addExtension Extension/basicConstraints true
                                 (BasicConstraints. false))
                  (.addExtension Extension/extendedKeyUsage false
                                 (ExtendedKeyUsage. (Vector.
                                                      [KeyPurposeId/id_kp_clientAuth
                                                       KeyPurposeId/id_kp_serverAuth])))
                  (.addExtension Extension/subjectKeyIdentifier false
                                 (.createSubjectKeyIdentifier (JcaX509ExtensionUtils.)
                                                              (.getSubjectPublicKeyInfo csr)))
                  (.addExtension Extension/authorityKeyIdentifier false
                                 (.createAuthorityKeyIdentifier (JcaX509ExtensionUtils.) cert)))
        signer (.build
                 (JcaContentSignerBuilder. (str hash-alg "withRSA"))
                 private-key)
        certificate (.build builder signer)]
    (.getCertificate (JcaX509CertificateConverter.) certificate)))