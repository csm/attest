(ns catool.core
  (:require [clojure.java.io :refer [reader writer]])
  (:import [java.security KeyPairGenerator]
           [org.bouncycastle.asn1.x500 X500Name]
           [java.util Calendar Date Base64]
           [org.bouncycastle.asn1.x509 SubjectPublicKeyInfo Extension KeyUsage BasicConstraints]
           [org.bouncycastle.cert X509v3CertificateBuilder]
           [org.bouncycastle.operator.jcajce JcaContentSignerBuilder]
           [org.bouncycastle.cert.jcajce JcaX509CertificateConverter]
           [sun.security.provider X509Factory]
           [java.security.cert X509Certificate]
           [org.bouncycastle.openssl PEMParser]
           [org.bouncycastle.pkcs PKCS10CertificationRequest PKCS10CertificationRequestBuilder])
  (:gen-class))

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

(defn read-csr
  [source]
  (with-open [reader (PEMParser. (reader source))]
    (let [request (.readObject reader)]
      (if (instance? PKCS10CertificationRequest request)
        request
        (throw (IllegalArgumentException. "not a valid certificate signing request"))))))

(defn generate-csr
  "Generate a certificate signing request. Returns a pair of values:
   first, the private key, second, the signing request."
  [{:keys [key-length hash-alg ^String name]
    :or {key-length 4096 hash-alg "SHA256"}}]
  (let [subject (X500Name. name)
        keygen (doto (KeyPairGenerator/getInstance "RSA")
                 (.initialize key-length))
        key-pair (.generateKeyPair keygen)
        spki (SubjectPublicKeyInfo/getInstance (.getEncoded (.getPublic key-pair)))
        builder (PKCS10CertificationRequestBuilder. subject spki)
        signer (.build
                 (JcaContentSignerBuilder. (str hash-alg "withRSA"))
                 (.getPrivate key-pair))]
      [(.getPrivate key-pair) (.build builder signer)]))

(defn generate-ca-cert
  "Generates a new CA certificate."
  [{:keys [key-length hash-alg ^String name years]
    :or {key-length 4096 hash-alg "SHA256" name "CN=CA" years 20}}]
  (let [keygen (doto (KeyPairGenerator/getInstance "RSA")
                 (.initialize key-length))
        key-pair (.generateKeyPair keygen)
        subject (X500Name. name)
        expires (doto (Calendar/getInstance) (.add Calendar/YEAR years))
        spki (SubjectPublicKeyInfo/getInstance (.getEncoded (.getPublic key-pair)))
        builder (X509v3CertificateBuilder. subject
                                           (biginteger 1N)
                                           (Date.)
                                           (.getTime expires)
                                           subject
                                           spki)
        _ (.addExtension builder Extension/keyUsage true (KeyUsage. (bit-or (KeyUsage/keyCertSign) (KeyUsage/cRLSign) (KeyUsage/digitalSignature))))
        _ (.addExtension builder Extension/basicConstraints true (BasicConstraints. true))
        signer (.build
                 (JcaContentSignerBuilder. (str hash-alg "withRSA"))
                 (.getPrivate key-pair))
        certificate (.build builder signer)]
    (.getCertificate (JcaX509CertificateConverter.) certificate)))

(defn generate-root-cert
  [{:keys [key-length hash-alg subject years]
    :or {key-length 4096 hash-alg "SHA256" years 1}}]
  ())