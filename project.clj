(defproject attest "0.1.0-SNAPSHOT"
  :description "Library and app for wrangling certificates"
  :url "https://github.com/csm/attest"
  :license {:name "Eclipse Public License"
            :url "http://www.eclipse.org/legal/epl-v10.html"}
  :dependencies [[org.clojure/clojure "1.8.0"]
                 [org.bouncycastle/bcpkix-jdk15on "1.55"]]
  :main ^:skip-aot attest.main
  :target-path "target/%s"
  :profiles {:uberjar {:aot :all}})
