(ns attest.main
  (:require [attest.core :refer :all]
            [clojure.java.io :refer [file]]
            [clojure.tools.cli :as cli])
  (:gen-class)
  (:import [java.io Console File]))

(defn common-opts
  [args usage summary files]
  (when (:help (:options args))
    (println usage)
    (newline)
    (println summary)
    (newline)
    (println (:summary args))
    (System/exit 0))
  (when (:errors args)
    (doall
      (for [error (:errors args)]
        (println error)))
    (System/exit 1))
  (when (and (not-any? #(.isAbsolute (file (-> args :options %))) files)
             (not (.exists (file (-> args :options :dir)))))
    (println "Output directory" (.getAbsolutePath (file (-> args :options :dir))) "does not exist")
    (System/exit 1)))

(defn get-password
  [args]
  (or (when-let [password (:password (:options args))]
        (.toCharArray password))
      (.readPassword (System/console) "Enter private key password:" (into-array []))))

(defn file-path
  [^File dir ^File path]
  (if (.isAbsolute path)
    path
    (file dir path)))

(defn init-ca
  [args]
  (let [options [["-a" "--alg ALG" "Set signature algorithm"
                  :default "RSA"]
                 ["-d" "--dir DIR" "Set output directory"
                  :default "."]
                 ["-h" "--hash ALG" "Set signature hash algorithm."
                  :default "SHA256"]
                 ["-l" "--key-length BITS" "Set key length"
                  :default 4096
                  :parse-fn (fn [s] (Integer/parseInt s))]
                 ["-n" "--name NAME" "Set certificate subject name"]
                 ["-o" "--output FILE" "Set certificate output file" :default "cert.pem"]
                 ["-O" "--key-output FILE" "Set private key output file" :default "key.pem"]
                 ["-p" "--password PASSWORD" "Specify private key password"]
                 [nil "--help" "Show this help and exit"]]
        args (cli/parse-opts args options)]
    (common-opts args "Usage: attest init [options]" "Generate a new self-signed root certificate."
                 [:output :key-output])
    (let [password (get-password args)
          key-pair (generate-key-pair :alg (-> args :options :alg)
                                      :key-length (-> args :options :key-length))
          cert (generate-root-cert key-pair :name (-> args :options :name)
                                   :hash-alg (-> args :options :hash))
          cert-file (file-path (file (-> args :options :dir)) (file (-> args :options :output)))
          key-file (file-path (file (-> args :options :dir)) (file (-> args :options :output)))]
      (write-cert cert cert-file)
      (write-private-key (.getPrivate key-pair) password key-file))))

(defn issue-ca
  [args]
  (let [options [["-d" "--dir DIR" "Path to outut directory" :default "."]
                 ["-r" "--request FILE" "Path to certificate signing request."]
                 ["-c" "--certificate FILE" "Path to signing certificate."]
                 ["-k" "--private-key FILE" "Path to private key."]
                 ["-o" "--output FILE" "Set path to output new cert."
                  :default "cert.pem"]
                 ["-p" "--password PASSWORD" "Private key password."]
                 ["-s" "--serial NUM" "Set new cert serial number."
                  :parse-fn (fn [s] (bigint s))]
                 ["-y" "--years NUM" "Set validity to this many years."
                  :default 1
                  :parse-fn (fn [s] (Integer/parseInt s))]
                 [nil "--help" "Show this help and exit."]]
        args (cli/parse-opts args options)]
    (common-opts args "Usage: attest issue-ca -r request [options]"
                 "Generates a new CA certificate from a certificate signing request."
                 [:output])
    (let [csr (read-csr (-> args :options :request))
          password (get-password args)
          cert (read-cert (-> args :options :certificate))
          private-key (read-private-key (-> args :options :private-key) password)
          new-cert (generate-ca-cert cert private-key csr (-> args :options :serial)
                                     :years (-> args :options :years))
          cert-path (file-path (file (-> args :options :dir)) (file (-> args :options :output)))]
      (write-cert new-cert cert-path))))

(defn issue-client
  [args])

(defn req
  [args]
  (let [options [["-a" "--alg ALG" "Set signature algorithm"
                  :default "RSA"]
                 ["-d" "--dir DIR" "Set output directory"
                  :default "."]
                 ["-h" "--hash ALG" "Set signature hash algorithm."
                  :default "SHA256"]
                 ["-l" "--key-length BITS" "Set key length"
                  :default 4096
                  :parse-fn (fn [s] (Integer/parseInt s))]
                 ["-n" "--name NAME" "Set subject name" :required true]
                 ["-o" "--output FILE" "Set certificate output file" :default "csr.pem"]
                 ["-O" "--key-output FILE" "Set private key output file" :default "key.pem"]
                 ["-p" "--password PASSWORD" "Specify password"]
                 [nil "--help" "Show this help and exit."]]
        args (cli/parse-opts args options)]
    (common-opts args "Usage: attest req [options]" "Generate a certificate signing request."
                 [:output :key-output])
    (let [password (if-let [password (-> args :options :password)]
                     (.toCharArray password)
                     (.readPassword (System/console) "Enter private key password:" (into-array [])))
          key-pair (generate-key-pair :key-length (-> args :options :key-length)
                                      :alg (-> args :options :alg))
          csr (generate-csr (-> args :options :name) key-pair
                            :hash-alg (-> args :options :hash))
          csr-file (if (.isAbsolute (file (-> args :options :output)))
                     (file (-> args :options :output))
                     (file (-> args :options :dir) (-> args :options :output)))
          key-file (if (.isAbsolute (file (-> args :options :key-output)))
                     (file (-> args :options :key-output))
                     (file (-> args :options :dir) (-> args :options :key-output)))]
      (write-csr csr csr-file)
      (write-private-key (.getPrivate key-pair) password key-file))))

(defn print-commands
  []
  (println "Usage: attest command [options]

Use `attest command --help' for help on command.

Commands include:

  init           Initialize a certificate authority.
  issue-ca       Issue a CA certificate.
  issue-client   Issue a client certificate.
  req            Generate a certificate signing request."))

(defn -main
  "I don't do a whole lot ... yet."
  [& args]
  (init!)
  (case (first args)
    "init" (init-ca (rest args))
    "issue-ca" (issue-ca (rest args))
    "issue-client" (issue-client (rest args))
    "req" (req (rest args))
    (print-commands)))
