(ns attest.core-test
  (:require [clojure.test :refer :all]
            [attest.core :refer :all])
  (:import [java.io StringWriter StringReader]
           [java.security.cert X509Certificate PKIXBuilderParameters TrustAnchor X509CertSelector CertPathBuilder CertStore CollectionCertStoreParameters CertPathValidator PKIXParameters]
           [javax.security.auth.x500 X500Principal]))

(def google-cert "-----BEGIN CERTIFICATE-----\nMIIgNzCCHx+gAwIBAgIIeOD67YfJe7IwDQYJKoZIhvcNAQELBQAwSTELMAkGA1UE\nBhMCVVMxEzARBgNVBAoTCkdvb2dsZSBJbmMxJTAjBgNVBAMTHEdvb2dsZSBJbnRl\ncm5ldCBBdXRob3JpdHkgRzIwHhcNMTYwODI0MTAxOTMwWhcNMTYxMTE2MTAxMDAw\nWjBkMQswCQYDVQQGEwJVUzETMBEGA1UECAwKQ2FsaWZvcm5pYTEWMBQGA1UEBwwN\nTW91bnRhaW4gVmlldzETMBEGA1UECgwKR29vZ2xlIEluYzETMBEGA1UEAwwKZ29v\nZ2xlLmNvbTCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBAOakOjcIU3o5\njIWwqYYNi5hIvCadxhyg3/ljfz0CrZEYnMl8wg+2EfomHZxAfhwIo0MffRomRAzO\n2B5ggIxh9uQXk35+3gFVI9R2o6M1QTHSdzupZetA8K3B713YoGyhN7si7yneXeSx\nuOkfNd0zcYT2InYBEoC8ZW0Mp7huZkgpWsH8n/tMmUWAoHmrAnPdjl9osFNbNYee\ndf9DQtfibGZLqASCZwoAgqoUwaCOOhgOZBUK9/EI4LXIMDK//OgrDgfRmVSl3T+U\nDNZLau5udKlVBq/4F1SAldvoDNw7qJYroo3X9KkeqGCG3vMxv4HKltMU3zuy3HRk\nWqoBsYSGYHsCAwEAAaOCHQYwgh0CMB0GA1UdJQQWMBQGCCsGAQUFBwMBBggrBgEF\nBQcDAjCCG9IGA1UdEQSCG8kwghvFggpnb29nbGUuY29tggoqLjJtZG4ubmV0gg0q\nLmFuZHJvaWQuY29tghYqLmFwcGVuZ2luZS5nb29nbGUuY29tghQqLmF1LmRvdWJs\nZWNsaWNrLm5ldIILKi5jYy1kdC5jb22CEiouY2xvdWQuZ29vZ2xlLmNvbYIUKi5k\nZS5kb3VibGVjbGljay5uZXSCESouZG91YmxlY2xpY2suY29tghEqLmRvdWJsZWNs\naWNrLm5ldIIVKi5mbHMuZG91YmxlY2xpY2submV0ghQqLmZyLmRvdWJsZWNsaWNr\nLm5ldIIWKi5nb29nbGUtYW5hbHl0aWNzLmNvbYILKi5nb29nbGUuYWOCCyouZ29v\nZ2xlLmFkggsqLmdvb2dsZS5hZYILKi5nb29nbGUuYWaCCyouZ29vZ2xlLmFnggsq\nLmdvb2dsZS5hbIILKi5nb29nbGUuYW2CCyouZ29vZ2xlLmFzggsqLmdvb2dsZS5h\ndIILKi5nb29nbGUuYXqCCyouZ29vZ2xlLmJhggsqLmdvb2dsZS5iZYILKi5nb29n\nbGUuYmaCCyouZ29vZ2xlLmJnggsqLmdvb2dsZS5iaYILKi5nb29nbGUuYmqCCyou\nZ29vZ2xlLmJzggsqLmdvb2dsZS5idIILKi5nb29nbGUuYnmCCyouZ29vZ2xlLmNh\nggwqLmdvb2dsZS5jYXSCCyouZ29vZ2xlLmNjggsqLmdvb2dsZS5jZIILKi5nb29n\nbGUuY2aCCyouZ29vZ2xlLmNnggsqLmdvb2dsZS5jaIILKi5nb29nbGUuY2mCCyou\nZ29vZ2xlLmNsggsqLmdvb2dsZS5jbYILKi5nb29nbGUuY26CDiouZ29vZ2xlLmNv\nLmFvgg4qLmdvb2dsZS5jby5id4IOKi5nb29nbGUuY28uY2uCDiouZ29vZ2xlLmNv\nLmNygg4qLmdvb2dsZS5jby5odYIOKi5nb29nbGUuY28uaWSCDiouZ29vZ2xlLmNv\nLmlsgg4qLmdvb2dsZS5jby5pbYIOKi5nb29nbGUuY28uaW6CDiouZ29vZ2xlLmNv\nLmplgg4qLmdvb2dsZS5jby5qcIIOKi5nb29nbGUuY28ua2WCDiouZ29vZ2xlLmNv\nLmtygg4qLmdvb2dsZS5jby5sc4IOKi5nb29nbGUuY28ubWGCDiouZ29vZ2xlLmNv\nLm16gg4qLmdvb2dsZS5jby5ueoIOKi5nb29nbGUuY28udGiCDiouZ29vZ2xlLmNv\nLnR6gg4qLmdvb2dsZS5jby51Z4IOKi5nb29nbGUuY28udWuCDiouZ29vZ2xlLmNv\nLnV6gg4qLmdvb2dsZS5jby52ZYIOKi5nb29nbGUuY28udmmCDiouZ29vZ2xlLmNv\nLnphgg4qLmdvb2dsZS5jby56bYIOKi5nb29nbGUuY28ueneCDCouZ29vZ2xlLmNv\nbYIPKi5nb29nbGUuY29tLmFmgg8qLmdvb2dsZS5jb20uYWeCDyouZ29vZ2xlLmNv\nbS5haYIPKi5nb29nbGUuY29tLmFygg8qLmdvb2dsZS5jb20uYXWCDyouZ29vZ2xl\nLmNvbS5iZIIPKi5nb29nbGUuY29tLmJogg8qLmdvb2dsZS5jb20uYm6CDyouZ29v\nZ2xlLmNvbS5ib4IPKi5nb29nbGUuY29tLmJygg8qLmdvb2dsZS5jb20uYnmCDyou\nZ29vZ2xlLmNvbS5ieoIPKi5nb29nbGUuY29tLmNugg8qLmdvb2dsZS5jb20uY2+C\nDyouZ29vZ2xlLmNvbS5jdYIPKi5nb29nbGUuY29tLmN5gg8qLmdvb2dsZS5jb20u\nZG+CDyouZ29vZ2xlLmNvbS5lY4IPKi5nb29nbGUuY29tLmVngg8qLmdvb2dsZS5j\nb20uZXSCDyouZ29vZ2xlLmNvbS5maoIPKi5nb29nbGUuY29tLmdlgg8qLmdvb2ds\nZS5jb20uZ2iCDyouZ29vZ2xlLmNvbS5naYIPKi5nb29nbGUuY29tLmdygg8qLmdv\nb2dsZS5jb20uZ3SCDyouZ29vZ2xlLmNvbS5oa4IPKi5nb29nbGUuY29tLmlxgg8q\nLmdvb2dsZS5jb20uam2CDyouZ29vZ2xlLmNvbS5qb4IPKi5nb29nbGUuY29tLmto\ngg8qLmdvb2dsZS5jb20ua3eCDyouZ29vZ2xlLmNvbS5sYoIPKi5nb29nbGUuY29t\nLmx5gg8qLmdvb2dsZS5jb20ubW2CDyouZ29vZ2xlLmNvbS5tdIIPKi5nb29nbGUu\nY29tLm14gg8qLmdvb2dsZS5jb20ubXmCDyouZ29vZ2xlLmNvbS5uYYIPKi5nb29n\nbGUuY29tLm5mgg8qLmdvb2dsZS5jb20ubmeCDyouZ29vZ2xlLmNvbS5uaYIPKi5n\nb29nbGUuY29tLm5wgg8qLmdvb2dsZS5jb20ubnKCDyouZ29vZ2xlLmNvbS5vbYIP\nKi5nb29nbGUuY29tLnBhgg8qLmdvb2dsZS5jb20ucGWCDyouZ29vZ2xlLmNvbS5w\nZ4IPKi5nb29nbGUuY29tLnBogg8qLmdvb2dsZS5jb20ucGuCDyouZ29vZ2xlLmNv\nbS5wbIIPKi5nb29nbGUuY29tLnBygg8qLmdvb2dsZS5jb20ucHmCDyouZ29vZ2xl\nLmNvbS5xYYIPKi5nb29nbGUuY29tLnJ1gg8qLmdvb2dsZS5jb20uc2GCDyouZ29v\nZ2xlLmNvbS5zYoIPKi5nb29nbGUuY29tLnNngg8qLmdvb2dsZS5jb20uc2yCDyou\nZ29vZ2xlLmNvbS5zdoIPKi5nb29nbGUuY29tLnRqgg8qLmdvb2dsZS5jb20udG6C\nDyouZ29vZ2xlLmNvbS50coIPKi5nb29nbGUuY29tLnR3gg8qLmdvb2dsZS5jb20u\ndWGCDyouZ29vZ2xlLmNvbS51eYIPKi5nb29nbGUuY29tLnZjgg8qLmdvb2dsZS5j\nb20udmWCDyouZ29vZ2xlLmNvbS52boILKi5nb29nbGUuY3aCCyouZ29vZ2xlLmN6\nggsqLmdvb2dsZS5kZYILKi5nb29nbGUuZGqCCyouZ29vZ2xlLmRrggsqLmdvb2ds\nZS5kbYILKi5nb29nbGUuZHqCCyouZ29vZ2xlLmVlggsqLmdvb2dsZS5lc4IMKi5n\nb29nbGUuZXVzggsqLmdvb2dsZS5maYILKi5nb29nbGUuZm2CCyouZ29vZ2xlLmZy\nggwqLmdvb2dsZS5mcmyCCyouZ29vZ2xlLmdhggwqLmdvb2dsZS5nYWyCCyouZ29v\nZ2xlLmdlggsqLmdvb2dsZS5nZ4ILKi5nb29nbGUuZ2yCCyouZ29vZ2xlLmdtggsq\nLmdvb2dsZS5ncIILKi5nb29nbGUuZ3KCCyouZ29vZ2xlLmd5ggsqLmdvb2dsZS5o\na4ILKi5nb29nbGUuaG6CCyouZ29vZ2xlLmhyggsqLmdvb2dsZS5odIILKi5nb29n\nbGUuaHWCCyouZ29vZ2xlLmllggsqLmdvb2dsZS5pbYILKi5nb29nbGUuaW6CDSou\nZ29vZ2xlLmluZm+CCyouZ29vZ2xlLmlxggsqLmdvb2dsZS5pcoILKi5nb29nbGUu\naXOCCyouZ29vZ2xlLml0gg4qLmdvb2dsZS5pdC5hb4ILKi5nb29nbGUuamWCCyou\nZ29vZ2xlLmpvgg0qLmdvb2dsZS5qb2JzggsqLmdvb2dsZS5qcIILKi5nb29nbGUu\na2eCCyouZ29vZ2xlLmtpggsqLmdvb2dsZS5reoILKi5nb29nbGUubGGCCyouZ29v\nZ2xlLmxpggsqLmdvb2dsZS5sa4ILKi5nb29nbGUubHSCCyouZ29vZ2xlLmx1ggsq\nLmdvb2dsZS5sdoILKi5nb29nbGUubWSCCyouZ29vZ2xlLm1lggsqLmdvb2dsZS5t\nZ4ILKi5nb29nbGUubWuCCyouZ29vZ2xlLm1sggsqLmdvb2dsZS5tboILKi5nb29n\nbGUubXOCCyouZ29vZ2xlLm11ggsqLmdvb2dsZS5tdoILKi5nb29nbGUubXeCCyou\nZ29vZ2xlLm5lgg4qLmdvb2dsZS5uZS5qcIIMKi5nb29nbGUubmV0ggsqLmdvb2ds\nZS5uZ4ILKi5nb29nbGUubmyCCyouZ29vZ2xlLm5vggsqLmdvb2dsZS5ucoILKi5n\nb29nbGUubnWCDyouZ29vZ2xlLm9mZi5haYILKi5nb29nbGUucGuCCyouZ29vZ2xl\nLnBsggsqLmdvb2dsZS5wboILKi5nb29nbGUucHOCCyouZ29vZ2xlLnB0ggsqLmdv\nb2dsZS5yb4ILKi5nb29nbGUucnOCCyouZ29vZ2xlLnJ1ggsqLmdvb2dsZS5yd4IL\nKi5nb29nbGUuc2OCCyouZ29vZ2xlLnNlggsqLmdvb2dsZS5zaIILKi5nb29nbGUu\nc2mCCyouZ29vZ2xlLnNrggsqLmdvb2dsZS5zbYILKi5nb29nbGUuc26CCyouZ29v\nZ2xlLnNvggsqLmdvb2dsZS5zcoILKi5nb29nbGUuc3SCCyouZ29vZ2xlLnRkggwq\nLmdvb2dsZS50ZWyCCyouZ29vZ2xlLnRnggsqLmdvb2dsZS50a4ILKi5nb29nbGUu\ndGyCCyouZ29vZ2xlLnRtggsqLmdvb2dsZS50boILKi5nb29nbGUudG+CCyouZ29v\nZ2xlLnR0ggsqLmdvb2dsZS51YYILKi5nb29nbGUudXOCCyouZ29vZ2xlLnV6ggsq\nLmdvb2dsZS52Z4ILKi5nb29nbGUudnWCCyouZ29vZ2xlLndzghIqLmdvb2dsZWFk\nYXBpcy5jb22CFSouZ29vZ2xlYWRzc2VydmluZy5jboIPKi5nb29nbGVhcGlzLmNu\nghQqLmdvb2dsZWNvbW1lcmNlLmNvbYIWKi5nb29nbGV1c2VyY29udGVudC5jboIR\nKi5nb29nbGV2aWRlby5jb22CDCouZ3N0YXRpYy5jboINKi5nc3RhdGljLmNvbYIK\nKi5ndnQxLmNvbYIKKi5ndnQyLmNvbYIUKi5qcC5kb3VibGVjbGljay5uZXSCFCou\nbWV0cmljLmdzdGF0aWMuY29tghQqLnVrLmRvdWJsZWNsaWNrLm5ldIIMKi51cmNo\naW4uY29tghAqLnVybC5nb29nbGUuY29tghYqLnlvdXR1YmUtbm9jb29raWUuY29t\ngg0qLnlvdXR1YmUuY29tghYqLnlvdXR1YmVlZHVjYXRpb24uY29tggsqLnl0aW1n\nLmNvbYIVYWQubW8uZG91YmxlY2xpY2submV0ghphbmRyb2lkLmNsaWVudHMuZ29v\nZ2xlLmNvbYILYW5kcm9pZC5jb22CD2RvdWJsZWNsaWNrLm5ldIIEZy5jb4IGZ29v\nLmdsghRnb29nbGUtYW5hbHl0aWNzLmNvbYIJZ29vZ2xlLmFjgglnb29nbGUuYWSC\nCWdvb2dsZS5hZYIJZ29vZ2xlLmFmgglnb29nbGUuYWeCCWdvb2dsZS5hbIIJZ29v\nZ2xlLmFtgglnb29nbGUuYXOCCWdvb2dsZS5hdIIJZ29vZ2xlLmF6gglnb29nbGUu\nYmGCCWdvb2dsZS5iZYIJZ29vZ2xlLmJmgglnb29nbGUuYmeCCWdvb2dsZS5iaYIJ\nZ29vZ2xlLmJqgglnb29nbGUuYnOCCWdvb2dsZS5idIIJZ29vZ2xlLmJ5gglnb29n\nbGUuY2GCCmdvb2dsZS5jYXSCCWdvb2dsZS5jY4IJZ29vZ2xlLmNkgglnb29nbGUu\nY2aCCWdvb2dsZS5jZ4IJZ29vZ2xlLmNogglnb29nbGUuY2mCCWdvb2dsZS5jbIIJ\nZ29vZ2xlLmNtgglnb29nbGUuY26CDGdvb2dsZS5jby5hb4IMZ29vZ2xlLmNvLmJ3\nggxnb29nbGUuY28uY2uCDGdvb2dsZS5jby5jcoIMZ29vZ2xlLmNvLmh1ggxnb29n\nbGUuY28uaWSCDGdvb2dsZS5jby5pbIIMZ29vZ2xlLmNvLmltggxnb29nbGUuY28u\naW6CDGdvb2dsZS5jby5qZYIMZ29vZ2xlLmNvLmpwggxnb29nbGUuY28ua2WCDGdv\nb2dsZS5jby5rcoIMZ29vZ2xlLmNvLmxzggxnb29nbGUuY28ubWGCDGdvb2dsZS5j\nby5teoIMZ29vZ2xlLmNvLm56ggxnb29nbGUuY28udGiCDGdvb2dsZS5jby50eoIM\nZ29vZ2xlLmNvLnVnggxnb29nbGUuY28udWuCDGdvb2dsZS5jby51eoIMZ29vZ2xl\nLmNvLnZlggxnb29nbGUuY28udmmCDGdvb2dsZS5jby56YYIMZ29vZ2xlLmNvLnpt\nggxnb29nbGUuY28ueneCDWdvb2dsZS5jb20uYWaCDWdvb2dsZS5jb20uYWeCDWdv\nb2dsZS5jb20uYWmCDWdvb2dsZS5jb20uYXKCDWdvb2dsZS5jb20uYXWCDWdvb2ds\nZS5jb20uYmSCDWdvb2dsZS5jb20uYmiCDWdvb2dsZS5jb20uYm6CDWdvb2dsZS5j\nb20uYm+CDWdvb2dsZS5jb20uYnKCDWdvb2dsZS5jb20uYnmCDWdvb2dsZS5jb20u\nYnqCDWdvb2dsZS5jb20uY26CDWdvb2dsZS5jb20uY2+CDWdvb2dsZS5jb20uY3WC\nDWdvb2dsZS5jb20uY3mCDWdvb2dsZS5jb20uZG+CDWdvb2dsZS5jb20uZWOCDWdv\nb2dsZS5jb20uZWeCDWdvb2dsZS5jb20uZXSCDWdvb2dsZS5jb20uZmqCDWdvb2ds\nZS5jb20uZ2WCDWdvb2dsZS5jb20uZ2iCDWdvb2dsZS5jb20uZ2mCDWdvb2dsZS5j\nb20uZ3KCDWdvb2dsZS5jb20uZ3SCDWdvb2dsZS5jb20uaGuCDWdvb2dsZS5jb20u\naXGCDWdvb2dsZS5jb20uam2CDWdvb2dsZS5jb20uam+CDWdvb2dsZS5jb20ua2iC\nDWdvb2dsZS5jb20ua3eCDWdvb2dsZS5jb20ubGKCDWdvb2dsZS5jb20ubHmCDWdv\nb2dsZS5jb20ubW2CDWdvb2dsZS5jb20ubXSCDWdvb2dsZS5jb20ubXiCDWdvb2ds\nZS5jb20ubXmCDWdvb2dsZS5jb20ubmGCDWdvb2dsZS5jb20ubmaCDWdvb2dsZS5j\nb20ubmeCDWdvb2dsZS5jb20ubmmCDWdvb2dsZS5jb20ubnCCDWdvb2dsZS5jb20u\nbnKCDWdvb2dsZS5jb20ub22CDWdvb2dsZS5jb20ucGGCDWdvb2dsZS5jb20ucGWC\nDWdvb2dsZS5jb20ucGeCDWdvb2dsZS5jb20ucGiCDWdvb2dsZS5jb20ucGuCDWdv\nb2dsZS5jb20ucGyCDWdvb2dsZS5jb20ucHKCDWdvb2dsZS5jb20ucHmCDWdvb2ds\nZS5jb20ucWGCDWdvb2dsZS5jb20ucnWCDWdvb2dsZS5jb20uc2GCDWdvb2dsZS5j\nb20uc2KCDWdvb2dsZS5jb20uc2eCDWdvb2dsZS5jb20uc2yCDWdvb2dsZS5jb20u\nc3aCDWdvb2dsZS5jb20udGqCDWdvb2dsZS5jb20udG6CDWdvb2dsZS5jb20udHKC\nDWdvb2dsZS5jb20udHeCDWdvb2dsZS5jb20udWGCDWdvb2dsZS5jb20udXmCDWdv\nb2dsZS5jb20udmOCDWdvb2dsZS5jb20udmWCDWdvb2dsZS5jb20udm6CCWdvb2ds\nZS5jdoIJZ29vZ2xlLmN6gglnb29nbGUuZGWCCWdvb2dsZS5kaoIJZ29vZ2xlLmRr\ngglnb29nbGUuZG2CCWdvb2dsZS5keoIJZ29vZ2xlLmVlgglnb29nbGUuZXOCCmdv\nb2dsZS5ldXOCCWdvb2dsZS5maYIJZ29vZ2xlLmZtgglnb29nbGUuZnKCCmdvb2ds\nZS5mcmyCCWdvb2dsZS5nYYIKZ29vZ2xlLmdhbIIJZ29vZ2xlLmdlgglnb29nbGUu\nZ2eCCWdvb2dsZS5nbIIJZ29vZ2xlLmdtgglnb29nbGUuZ3CCCWdvb2dsZS5ncoIJ\nZ29vZ2xlLmd5gglnb29nbGUuaGuCCWdvb2dsZS5oboIJZ29vZ2xlLmhygglnb29n\nbGUuaHSCCWdvb2dsZS5odYIJZ29vZ2xlLmllgglnb29nbGUuaW2CCWdvb2dsZS5p\nboILZ29vZ2xlLmluZm+CCWdvb2dsZS5pcYIJZ29vZ2xlLmlygglnb29nbGUuaXOC\nCWdvb2dsZS5pdIIMZ29vZ2xlLml0LmFvgglnb29nbGUuamWCCWdvb2dsZS5qb4IL\nZ29vZ2xlLmpvYnOCCWdvb2dsZS5qcIIJZ29vZ2xlLmtngglnb29nbGUua2mCCWdv\nb2dsZS5reoIJZ29vZ2xlLmxhgglnb29nbGUubGmCCWdvb2dsZS5sa4IJZ29vZ2xl\nLmx0gglnb29nbGUubHWCCWdvb2dsZS5sdoIJZ29vZ2xlLm1kgglnb29nbGUubWWC\nCWdvb2dsZS5tZ4IJZ29vZ2xlLm1rgglnb29nbGUubWyCCWdvb2dsZS5tboIJZ29v\nZ2xlLm1zgglnb29nbGUubXWCCWdvb2dsZS5tdoIJZ29vZ2xlLm13gglnb29nbGUu\nbmWCDGdvb2dsZS5uZS5qcIIKZ29vZ2xlLm5ldIIJZ29vZ2xlLm5ngglnb29nbGUu\nbmyCCWdvb2dsZS5ub4IJZ29vZ2xlLm5ygglnb29nbGUubnWCDWdvb2dsZS5vZmYu\nYWmCCWdvb2dsZS5wa4IJZ29vZ2xlLnBsgglnb29nbGUucG6CCWdvb2dsZS5wc4IJ\nZ29vZ2xlLnB0gglnb29nbGUucm+CCWdvb2dsZS5yc4IJZ29vZ2xlLnJ1gglnb29n\nbGUucneCCWdvb2dsZS5zY4IJZ29vZ2xlLnNlgglnb29nbGUuc2iCCWdvb2dsZS5z\naYIJZ29vZ2xlLnNrgglnb29nbGUuc22CCWdvb2dsZS5zboIJZ29vZ2xlLnNvggln\nb29nbGUuc3KCCWdvb2dsZS5zdIIJZ29vZ2xlLnRkggpnb29nbGUudGVsgglnb29n\nbGUudGeCCWdvb2dsZS50a4IJZ29vZ2xlLnRsgglnb29nbGUudG2CCWdvb2dsZS50\nboIJZ29vZ2xlLnRvgglnb29nbGUudHSCCWdvb2dsZS51YYIJZ29vZ2xlLnVzggln\nb29nbGUudXqCCWdvb2dsZS52Z4IJZ29vZ2xlLnZ1gglnb29nbGUud3OCEmdvb2ds\nZWNvbW1lcmNlLmNvbYILZ3N0YXRpYy5jb22CGXBvbGljeS5tdGEtc3RzLmdvb2ds\nZS5jb22CCnVyY2hpbi5jb22CCnd3dy5nb28uZ2yCCHlvdXR1LmJlggt5b3V0dWJl\nLmNvbYIUeW91dHViZWVkdWNhdGlvbi5jb20waAYIKwYBBQUHAQEEXDBaMCsGCCsG\nAQUFBzAChh9odHRwOi8vcGtpLmdvb2dsZS5jb20vR0lBRzIuY3J0MCsGCCsGAQUF\nBzABhh9odHRwOi8vY2xpZW50czEuZ29vZ2xlLmNvbS9vY3NwMB0GA1UdDgQWBBTn\nr08BnOxNXOjWIl5yUwITFIfQCDAMBgNVHRMBAf8EAjAAMB8GA1UdIwQYMBaAFErd\nBhYbvPZotXb1gba7Yhq6WoEvMCEGA1UdIAQaMBgwDAYKKwYBBAHWeQIFATAIBgZn\ngQwBAgIwMAYDVR0fBCkwJzAloCOgIYYfaHR0cDovL3BraS5nb29nbGUuY29tL0dJ\nQUcyLmNybDANBgkqhkiG9w0BAQsFAAOCAQEAhSyH+tohqkiCYL1WYL8jMGVW48T5\nTbygZCW0janbL9vDqOmRR9r+MeBwp0TYuj5/5cZZBPde7wY6hMVxKuG0qOgvN5+A\nVJPgV+DU3XkTZTrO/izyearXl4mrFBS4+Uhk/gxUdv3elUb0wATOQflTOtNVoi8Q\nUAlq4zCc1BXbjPeuVarjE2lmmapPQWsy652OamPQQ7vSz/Zr6Gl+BNR52XmA/PCJ\n/3e8exl2f1TnP2jKX1d3n2kFHzfJwKDfjxl2SkEjb/kXiBkDrdbsQO6wKdiZWOsI\n4ymc2U7GRMF4qGyZWpo84B5W2oWNiyfVSXTMG5dnr5Jmx35BA4Yg8bHtsw==\n-----END CERTIFICATE-----\n")
(def google-authority "-----BEGIN CERTIFICATE-----\nMIID8DCCAtigAwIBAgIDAjqSMA0GCSqGSIb3DQEBCwUAMEIxCzAJBgNVBAYTAlVT\nMRYwFAYDVQQKEw1HZW9UcnVzdCBJbmMuMRswGQYDVQQDExJHZW9UcnVzdCBHbG9i\nYWwgQ0EwHhcNMTUwNDAxMDAwMDAwWhcNMTcxMjMxMjM1OTU5WjBJMQswCQYDVQQG\nEwJVUzETMBEGA1UEChMKR29vZ2xlIEluYzElMCMGA1UEAxMcR29vZ2xlIEludGVy\nbmV0IEF1dGhvcml0eSBHMjCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEB\nAJwqBHdc2FCROgajguDYUEi8iT/xGXAaiEZ+4I/F8YnOIe5a/mENtzJEiaB0C1NP\nVaTOgmKV7utZX8bhBYASxF6UP7xbSDj0U/ck5vuR6RXEz/RTDfRK/J9U3n2+oGtv\nh8DQUB8oMANA2ghzUWx//zo8pzcGjr1LEQTrfSTe5vn8MXH7lNVg8y5Kr0LSy+rE\nahqyzFPdFUuLH8gZYR/Nnag+YyuENWllhMgZxUYi+FOVvuOAShDGKuy6lyARxzmZ\nEASg8GF6lSWMTlJ14rbtCMoU/M4iarNOz0YDl5cDfsCx3nuvRTPPuj5xt970JSXC\nDTWJnZ37DhF5iR43xa+OcmkCAwEAAaOB5zCB5DAfBgNVHSMEGDAWgBTAephojYn7\nqwVkDBF9qn1luMrMTjAdBgNVHQ4EFgQUSt0GFhu89mi1dvWBtrtiGrpagS8wDgYD\nVR0PAQH/BAQDAgEGMC4GCCsGAQUFBwEBBCIwIDAeBggrBgEFBQcwAYYSaHR0cDov\nL2cuc3ltY2QuY29tMBIGA1UdEwEB/wQIMAYBAf8CAQAwNQYDVR0fBC4wLDAqoCig\nJoYkaHR0cDovL2cuc3ltY2IuY29tL2NybHMvZ3RnbG9iYWwuY3JsMBcGA1UdIAQQ\nMA4wDAYKKwYBBAHWeQIFATANBgkqhkiG9w0BAQsFAAOCAQEACE4Ep4B/EBZDXgKt\n10KA9LCO0q6z6xF9kIQYfeeQFftJf6iZBZG7esnWPDcYCZq2x5IgBzUzCeQoY3IN\ntOAynIeYxBt2iWfBUFiwE6oTGhsypb7qEZVMSGNJ6ZldIDfM/ippURaVS6neSYLA\nEHD0LPPsvCQk0E6spdleHm2SwaesSDWB+eXknGVpzYekQVA/LlelkVESWA6MCaGs\neqQSpSfzmhCXfVUDBvdmWF9fZOGrXW2lOUh1mEwpWjqN0yvKnFUEv/TmFNWArCbt\nF4mmk2xcpMy48GaOZON9muIAs0nH5Aqq3VuDx3CQRk6+0NtZlmwu9RY23nHMAcIS\nwSHGFg==\n-----END CERTIFICATE-----\n")
(def geotrust-cert "-----BEGIN CERTIFICATE-----\nMIIDfTCCAuagAwIBAgIDErvmMA0GCSqGSIb3DQEBBQUAME4xCzAJBgNVBAYTAlVT\nMRAwDgYDVQQKEwdFcXVpZmF4MS0wKwYDVQQLEyRFcXVpZmF4IFNlY3VyZSBDZXJ0\naWZpY2F0ZSBBdXRob3JpdHkwHhcNMDIwNTIxMDQwMDAwWhcNMTgwODIxMDQwMDAw\nWjBCMQswCQYDVQQGEwJVUzEWMBQGA1UEChMNR2VvVHJ1c3QgSW5jLjEbMBkGA1UE\nAxMSR2VvVHJ1c3QgR2xvYmFsIENBMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIB\nCgKCAQEA2swYYzD99BcjGlZ+W988bDjkcbd4kdS8odhM+KhDtgPpTSEHCIjaWC9m\nOSm9BXiLnTjoBbdqfnGk5sRgprDvgOSJKA+eJdbtg/OtppHHmMlCGDUUna2YRpIu\nT8rxh0PBFpVXLVDviS2Aelet8u5fa9IAjbkU+BQVNdnARqN7csiRv8lVK83Qlz6c\nJmTM386DGXHKTubU1XupGc1V3sjs0l44U+VcT4wt/lAjNvxm5suOpDkZALeVAjmR\nCw7+OC7RHQWa9k0+bw8HHa8sHo9gOeL6NlMTOdReJivbPagUvTLrGAMoUgRx5asz\nPeE4uwc2hGKceeoWMPRfwCvocWvk+QIDAQABo4HwMIHtMB8GA1UdIwQYMBaAFEjm\naPkr0rKV10fYIyAQTzOYkJ/UMB0GA1UdDgQWBBTAephojYn7qwVkDBF9qn1luMrM\nTjAPBgNVHRMBAf8EBTADAQH/MA4GA1UdDwEB/wQEAwIBBjA6BgNVHR8EMzAxMC+g\nLaArhilodHRwOi8vY3JsLmdlb3RydXN0LmNvbS9jcmxzL3NlY3VyZWNhLmNybDBO\nBgNVHSAERzBFMEMGBFUdIAAwOzA5BggrBgEFBQcCARYtaHR0cHM6Ly93d3cuZ2Vv\ndHJ1c3QuY29tL3Jlc291cmNlcy9yZXBvc2l0b3J5MA0GCSqGSIb3DQEBBQUAA4GB\nAHbhEm5OSxYShjAGsoEIz/AIx8dxfmbuwu3UOx//8PDITtZDOLC5MH0Y0FWDomrL\nNhGc6Ehmo21/uBPUR/6LWlxz/K7ZGzIZOKuXNBSqltLroxwUCEm2u+WR74M26x1W\nb8ravHNjkOR/ez4iyz0H7V84dJzjA1BOoa+Y7mHyhD8S\n-----END CERTIFICATE-----\n")

(deftest test-ca-cert-gen
  (let [key-pair (generate-key-pair)
        cert (generate-root-cert key-pair)
        encoded (let [w (StringWriter.)]
                  (write-cert cert w)
                  (.toString w))
        decoded (read-cert (StringReader. encoded))]
      (is (= cert decoded))))

(defn test-cert
  [cert issuer subject]
  (is (= (.getSubjectX500Principal cert) subject))
  (is (= (.getIssuerX500Principal cert) issuer)))

(deftest test-parse-certs
  (let [cert (read-cert (StringReader. google-cert))]
    (test-cert cert
               (X500Principal. "CN=Google Internet Authority G2,O=Google Inc,C=US")
               (X500Principal. "CN=google.com,O=Google Inc,L=Mountain View,ST=California,C=US")))
  (let [cert (read-cert (StringReader. google-authority))]
    (test-cert cert
               (X500Principal. "CN=GeoTrust Global CA,O=GeoTrust Inc.,C=US")
               (X500Principal. "CN=Google Internet Authority G2,O=Google Inc,C=US")))
  (let [cert (read-cert (StringReader. geotrust-cert))]
    (test-cert cert
               (X500Principal. "OU=Equifax Secure Certificate Authority,O=Equifax,C=US")
               (X500Principal. "CN=GeoTrust Global CA,O=GeoTrust Inc.,C=US"))))

(deftest do-we-generate-valid-certs?
  (let [root-keys (generate-key-pair)
        root-cert (generate-root-cert root-keys :name "CN=Root")
        _ (println "ROOT CERT:\n" root-cert)
        ca-key-pair (generate-key-pair)
        ca-csr (generate-csr "CN=Test CA" ca-key-pair)
        ca-cert (generate-ca-cert root-cert (.getPrivate root-keys) ca-csr 2N)
        _ (println "CA CERT:\n" ca-cert)
        client-key-pair (generate-key-pair)
        client-csr (generate-csr "CN=Client Cert" client-key-pair)
        client-cert (generate-user-cert ca-cert (.getPrivate ca-key-pair) client-csr 3N)
        _ (println "CLIENT CERT:\n" client-cert)
        selector (doto (X509CertSelector.) (.setCertificate client-cert))
        builder-params (doto
                         (PKIXBuilderParameters. #{(TrustAnchor. root-cert nil)}
                                                 selector)
                         (.setRevocationEnabled false)
                         (.addCertStore (CertStore/getInstance "Collection"
                                                               (CollectionCertStoreParameters.
                                                                 [client-cert ca-cert]))))
        builder (CertPathBuilder/getInstance "PKIX")
        build-result (.build builder builder-params)
        validator-params (doto (PKIXParameters. #{(TrustAnchor. root-cert nil)})
                           (.setRevocationEnabled false))
        validator (CertPathValidator/getInstance "PKIX")
        _ (.validate validator (.getCertPath build-result) validator-params)]
    (is true) ; builder/validator throws on failure
    ))