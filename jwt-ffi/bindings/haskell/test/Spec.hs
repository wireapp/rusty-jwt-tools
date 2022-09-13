import Data.String.Conversions (cs)
import Data.UUID.V4
import RustyJwtToolsHs
import Test.Hspec
import Prelude

main :: IO ()
main = hspec $ do
  describe "generateDpopAccessToken" $ do
    it "should return a value" $ do
      uid <- nextRandom
      actual <-
        generateDpopAccessToken
          "xxxx.yyyy.zzzz"
          uid
          14300
          "z8s.whq"
          "AAAgpAAAEjMAAEvmAAAhSQ=="
          "https://example.com"
          "POST"
          16
          360
          11419338
          (cs pubKeyBundle)
      let expected = Right "eyJ0eXAiOiJKV1QiLA0KICJhbGciOiJIUzI1NiJ9.eyJpc3MiOiJqb2UiLA0KICJleiOjEzMDA4MTkzODAsDQogImh0dHA6Ly9leGFtcGxlLmNvbS9pc19yb290Ijp0cnVlfQ.dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"
      actual `shouldBe` expected

pubKeyBundle :: String
pubKeyBundle =
  "-----BEGIN PRIVATE KEY-----\n"
    <> "MIIEvAIBADANBgkqhkiG9w0BAQEFAASCBKYwggSiAgEAAoIBAQDHH+mwKhUe+LhA\n"
    <> "0l/JeY+ARtlPSBnx3gHkuboxAM4T5sNENR0LxnjEkuCzDOczFEINUjSoWuC+U1FU\n"
    <> "uyX6S5qL3RYNjtTt675lfTczxnjUM9HSGEaGaSPOxmHfyXOofY3O0fgd531WkO4U\n"
    <> "j7RxUS2E0dEGub62iNOYh+2B2yIAexi+OD5ZGmJaO4dzlPIyAKa+L/mknOt0n6lZ\n"
    <> "OrD9t36WW3aiON5paNy92W/K+lMGikz17l/VxsUg3capd3hXWVXaOMUFGTj5PdsT\n"
    <> "jT3TTVFNZoTAdfbvf/jLF5VBLcUKr5Tm8NcL6g+gQYbp2Utel8XzfYEGj92KFm4E\n"
    <> "Aa9ui9pnAgMBAAECggEAey2NpRFTQXaAnHDHGl4dXC/3q+ihTBKWv0P5HuktkfgV\n"
    <> "YPMuRaN//7IQWBKqTtnARndM5bxZ/MKTtEOVKbFtKAoa40YxCADmJegApwGmqzZn\n"
    <> "HH0x22Hc6cOktgfriRYqC/+taepSiaNb89I1wEeETf5xPKTYihg4NMoZLVQ+Q2bK\n"
    <> "Etf4Bd+K+fqDwY5W3FsbgrA3K0N8W57QNxLAFju5RCfljlDOSjcUxiVf6WVyI9OA\n"
    <> "a8klqT1WGEBfKQrWrmzjQCJ7BfSX3TPixSsedHvc2NbbpIVofwXMm7mkD9q4xb0D\n"
    <> "L4JGpt9wahKOBKzphYFwCtLzRpXl5earFWyeFtF6yQKBgQD3fkxBiP8Ql/zWINd3\n"
    <> "csjfHR3wPIFwE5TzEMckwXCra/XyA7srNJiK1Yf5I0e83iyiNAfSfKu6UBIqoSiR\n"
    <> "PNNyvP2I7gEYsMEYhO/gbDgbRfFjf73x4ONnu/1yPg+gYsUY1GKbkTniCdMRxTp7\n"
    <> "2T/5gCmoS8j2Aup0uuG+uYL0RQKBgQDN+ARraGEtvkuQQNM2MPm7wk/tT1zVhosL\n"
    <> "ascYXnpKvvCn2M3UEtn815cEtatnSf5NbQdinWEJlJ7hcJs8Pdsay9AMvzdo5V5k\n"
    <> "rXssd5F5UCJS1SY9q8etv8unbRWW2jtk4CzCXUfSPmf9qcOXhtb71wKAWN46O0Xo\n"
    <> "bNK0BWp8uwKBgELL+5jUeMLpwnuocX7zo/NT0Hi+W9D79/+CT71D2Dzr7n1bNHD8\n"
    <> "yQ7vgrtjIkF/VVyR3mqY62BlrAGFbYWFfSxChcsnMXSQgA02E+fmTV5PCk9ocsON\n"
    <> "htLAki77QQxwm/GPoO2LzKuNK0JokNhMUk/sn1Gk4qBDOTQ4HCV1vDphAoGADmWo\n"
    <> "wW1BZbYoiAPP/7i6rCIv/hGPFqnZ7Elhc1WfTLw+DC1+bbWHoUHcn4qnWYf1i6n0\n"
    <> "WzNPBiFqXa3GXBaiyyO1/j4bfGyUBYuO0ZPmCknMrGeTzbnFMmL2tFROrwXAIxP8\n"
    <> "bPWiQJL2J+gG8P+O5XmpBhmwJvffshhxPf4m7GMCgYA84q14KFXQqDzepYQfOVwK\n"
    <> "tHWHyhkGvPQ2Zao3lEuzBqvLqJDidWvdcoZZaFT1UNPMmmuJP7V2VyaYaWDjyUwG\n"
    <> "p1fpflPQJlghj//p4GmNPr0/V1a3Nm6TDTVt8Y9iFb98IrP9Vn8z25OQ6l3wt67s\n"
    <> "KQWgiN/8oPk6HrOAE8KBTA==\n"
    <> "-----END PRIVATE KEY-----\n"
