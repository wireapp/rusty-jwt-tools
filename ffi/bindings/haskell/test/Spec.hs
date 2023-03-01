{-# OPTIONS_GHC -Wno-incomplete-uni-patterns #-}
import Data.String.Conversions (cs)
import Data.UUID.V4
import Data.UUID as UUID
import RustyJwtToolsHs
import Test.Hspec
import Prelude
import Data.Either

main :: IO ()
main = hspec $ do
  describe "generate_dpop_access_token" $ do
    it "should return an error when given nonsense values" $ do
      let pubKeyBundle :: String
          pubKeyBundle =
                "-----BEGIN PRIVATE KEY-----\n\
                \MC4CAQAwBQYDK2VwBCIEIFANnxZLNE4p+GDzWzR3wm/v8x/0bxZYkCyke1aTRucX\n\
                \-----END PRIVATE KEY-----\n\
                \-----BEGIN PUBLIC KEY-----\n\
                \MCowBQYDK2VwAyEACPvhIdimF20tOPjbb+fXJrwS2RKDp7686T90AZ0+Th8=\n\
                \-----END PUBLIC KEY-----\n"
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
      isRight actual `shouldBe` False
    it "should return a valid access token" $ do
      let pubKeyBundle :: String
          pubKeyBundle =
                "-----BEGIN PRIVATE KEY-----\n\
                \MC4CAQAwBQYDK2VwBCIEIKW3jzXCsRVgnclmiTu53Pu1/r6AUmnKDoghOOVMjozQ\n\
                \-----END PRIVATE KEY-----\n\
                \-----BEGIN PUBLIC KEY-----\n\
                \MCowBQYDK2VwAyEA7t9veqi02mPhllm44JXWga8m/l4JxUeQm3qPyMlerxY=\n\
                \-----END PUBLIC KEY-----\n"
      let Just uid = UUID.fromString "ebd272fb-82fd-432b-876c-7abda54ddb75"
      actual <-
        generateDpopAccessToken
          "eyJhbGciOiJFZERTQSIsInR5cCI6ImRwb3Arand0IiwiandrIjp7Imt0eSI6Ik9LUCIsImNydiI6IkVkMjU1MTkiLCJ4IjoiZzQwakI3V3pmb2ZCdkxCNVlybmlZM2ZPZU1WVGtfNlpfVnNZM0tBbnpOUSJ9fQ.eyJpYXQiOjE2Nzc2NzAwODEsImV4cCI6MTY3Nzc1NjQ4MSwibmJmIjoxNjc3NjcwMDgxLCJzdWIiOiJpbXBwOndpcmVhcHA9WldKa01qY3labUk0TW1aa05ETXlZamczTm1NM1lXSmtZVFUwWkdSaU56VS8xODllNDhjNmNhODZiNWQ0QGV4YW1wbGUub3JnIiwianRpIjoiZDE5ZWExYmItNWI0Ny00ZGJiLWE1MTktNjU0ZWRmMjU0MTQ0Iiwibm9uY2UiOiJZMkZVTjJaTlExUnZSV0l6Ympsa2RGRjFjWGhHZDJKbWFXUlRiamhXZVdRIiwiaHRtIjoiUE9TVCIsImh0dSI6Imh0dHA6Ly9sb2NhbGhvc3Q6NjQwNTQvIiwiY2hhbCI6IkJpMkpkUGk1eWVTTVdhZjA5TnJEZTVUQXFjZ0FnQmE3In0._PrwHUTS7EoAflXyNDlPNqGMbjKu-JuSXwkNPyryBQdg2gDIb20amsH05Ocih78Josz9h7lAB6FvAWsXKQB1Dw"
          uid
          1773935321869104596
          "example.org"
          "Y2FUN2ZNQ1RvRWIzbjlkdFF1cXhGd2JmaWRTbjhWeWQ"
          "http://localhost:64054/"
          "POST"
          2
          2082008461
          360
          (cs pubKeyBundle)
      isRight actual `shouldBe` True

