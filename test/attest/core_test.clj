(ns attest.core-test
  (:require [clojure.test :refer :all]
            [attest.core :refer :all])
  (:import [java.io StringWriter StringReader]))

(deftest test-ca-cert-gen
  (let [key-pair (generate-key-pair)
        cert (generate-ca-cert key-pair)
        encoded (let [w (StringWriter.)]
                  (write-cert cert w)
                  (.toString w))
        decoded (read-cert (StringReader. encoded))]
      (is (= cert decoded))))
