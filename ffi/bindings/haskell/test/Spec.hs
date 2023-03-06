{-# OPTIONS_GHC -Wno-incomplete-uni-patterns #-}

import Data.Either
import Data.String.Conversions (cs)
import Data.UUID as UUID
import Data.UUID.V4
import RustyJwtToolsHs
import Test.Hspec
import Prelude

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
            \MC4CAQAwBQYDK2VwBCIEIMROyHqEinw8EvFSNXp0X0suu6gMQvd9i/l9v9R9UnhH\n\
            \-----END PRIVATE KEY-----\n\
            \-----BEGIN PUBLIC KEY-----\n\
            \MCowBQYDK2VwAyEA5pDR/Yo4pkKUIxIody2fEQ56eIOW7UqeDeF7FG7WudA=\n\
            \-----END PUBLIC KEY-----\n"
      let Just uid = UUID.fromString "c5e21936-c3bc-4007-becb-0acf5972a5b3"
      let proofExpiring2038 =
            "eyJhbGciOiJFZERTQSIsInR5cCI6ImRwb3Arand0IiwiandrIjp7Imt0eSI6Ik9LUCIsImNydiI6IkVkMjU1MTkiLCJ4IjoiZ0tYSHpIV3QtRUh1N2ZQbmlWMXFXWGV2Rmk1eFNKd3RNcHJlSjBjdTZ3SSJ9fQ.eyJpYXQiOjE2NzgxMDcwMDksImV4cCI6MjA4ODA3NTAwOSwibmJmIjoxNjc4MTA3MDA5LCJzdWIiOiJpbXBwOndpcmVhcHA9WXpWbE1qRTVNelpqTTJKak5EQXdOMkpsWTJJd1lXTm1OVGszTW1FMVlqTS9lYWZhMDI1NzMwM2Q0MDYwQHdpcmUuY29tIiwianRpIjoiMmQzNzAzYTItNTc4Yi00MmRjLWE2MGUtYmM0NzA3OWVkODk5Iiwibm9uY2UiOiJRV1J4T1VaUVpYVnNTMlJZYjBGS05sWkhXbGgwYUV4amJUUmpTM2M1U2xnIiwiaHRtIjoiUE9TVCIsImh0dSI6Imh0dHBzOi8vd2lyZS5leGFtcGxlLmNvbS9jbGllbnRzLzE2OTMxODQ4MzIyNTQ3NTMxODcyL2FjY2Vzcy10b2tlbiIsImNoYWwiOiJZVE5HTkRSNlRqZHFabGRRZUVGYWVrMTZWMmhqYXpCVmJ6UlFWVXRWUlZJIn0.0J2sx5y0ubZ4NwmQhbKXDj6i5UWTx3cvuTPKbeXXOJFDamr-iFtE6sOnAQT90kfTx1cEoIyDfoUkj3h5GEanAA"
      actual <-
        generateDpopAccessToken
          proofExpiring2038
          uid
          16931848322547531872
          "wire.com"
          "QWRxOUZQZXVsS2RYb0FKNlZHWlh0aExjbTRjS3c5Slg"
          "https://wire.example.com/clients/16931848322547531872/access-token"
          "POST"
          5
          2136351646
          360
          (cs pubKeyBundle)
      isRight actual `shouldBe` True
