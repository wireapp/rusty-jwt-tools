{-# OPTIONS_GHC -Wno-incomplete-uni-patterns #-}

import Data.Either
import Data.UUID as UUID
import RustyJwtToolsHs
import Test.Hspec
import Prelude
import Data.Maybe

main :: IO ()
main = hspec $ do
  describe "generate_dpop_access_token" $ do
    it "should return an error when given wrong nonce" $ do
      actual <-
        generateDpopAccessToken
          proofExpiring2038
          uid
          clientId
          domain
          "foobar"
          url
          method
          maxSkewSeconds
          expiration
          now
          pubKeyBundle
      actual `shouldBe` Left "Error: 9"
    it "should return a valid access token" $ do
      actual <-
        generateDpopAccessToken
          proofExpiring2038
          uid
          clientId
          domain
          nonce
          url
          method
          maxSkewSeconds
          expiration
          now
          pubKeyBundle
      isRight actual `shouldBe` True

    where
      pubKeyBundle =
            "-----BEGIN PRIVATE KEY-----\n\
            \MC4CAQAwBQYDK2VwBCIEIMROyHqEinw8EvFSNXp0X0suu6gMQvd9i/l9v9R9UnhH\n\
            \-----END PRIVATE KEY-----\n\
            \-----BEGIN PUBLIC KEY-----\n\
            \MCowBQYDK2VwAyEA5pDR/Yo4pkKUIxIody2fEQ56eIOW7UqeDeF7FG7WudA=\n\
            \-----END PUBLIC KEY-----\n"
      uid = fromMaybe (error "invalid user id") $ UUID.fromString "c5e21936-c3bc-4007-becb-0acf5972a5b3"
      proofExpiring2038 =
            "eyJhbGciOiJFZERTQSIsInR5cCI6ImRwb3Arand0IiwiandrIjp7Imt0eSI6Ik9LUCIsImNydiI6IkVkMjU1MTkiLCJ4IjoiZ0tYSHpIV3QtRUh1N2ZQbmlWMXFXWGV2Rmk1eFNKd3RNcHJlSjBjdTZ3SSJ9fQ.eyJpYXQiOjE2NzgxMDcwMDksImV4cCI6MjA4ODA3NTAwOSwibmJmIjoxNjc4MTA3MDA5LCJzdWIiOiJpbXBwOndpcmVhcHA9WXpWbE1qRTVNelpqTTJKak5EQXdOMkpsWTJJd1lXTm1OVGszTW1FMVlqTS9lYWZhMDI1NzMwM2Q0MDYwQHdpcmUuY29tIiwianRpIjoiMmQzNzAzYTItNTc4Yi00MmRjLWE2MGUtYmM0NzA3OWVkODk5Iiwibm9uY2UiOiJRV1J4T1VaUVpYVnNTMlJZYjBGS05sWkhXbGgwYUV4amJUUmpTM2M1U2xnIiwiaHRtIjoiUE9TVCIsImh0dSI6Imh0dHBzOi8vd2lyZS5leGFtcGxlLmNvbS9jbGllbnRzLzE2OTMxODQ4MzIyNTQ3NTMxODcyL2FjY2Vzcy10b2tlbiIsImNoYWwiOiJZVE5HTkRSNlRqZHFabGRRZUVGYWVrMTZWMmhqYXpCVmJ6UlFWVXRWUlZJIn0.0J2sx5y0ubZ4NwmQhbKXDj6i5UWTx3cvuTPKbeXXOJFDamr-iFtE6sOnAQT90kfTx1cEoIyDfoUkj3h5GEanAA"

      clientId = 16931848322547531872
      domain = "wire.com"
      nonce = "QWRxOUZQZXVsS2RYb0FKNlZHWlh0aExjbTRjS3c5Slg"
      url = "https://wire.example.com/clients/16931848322547531872/access-token"
      method = "POST"
      maxSkewSeconds = 5
      expiration = 2136351646
      now = 360
