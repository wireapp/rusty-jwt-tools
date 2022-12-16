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
    <> "MC4CAQAwBQYDK2VwBCIEIFANnxZLNE4p+GDzWzR3wm/v8x/0bxZYkCyke1aTRucX\n"
    <> "-----END PRIVATE KEY-----\n"
    <> "-----BEGIN PUBLIC KEY-----\n"
    <> "MCowBQYDK2VwAyEACPvhIdimF20tOPjbb+fXJrwS2RKDp7686T90AZ0+Th8=\n"
    <> "-----END PUBLIC KEY-----\n"
