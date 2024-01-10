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
          handle
          teamId
          domain
          "foobar"
          url
          method
          maxSkewSeconds
          expiration
          now
          pubKeyBundle
      pending
      actual `shouldBe` Left "Error: 9"
    it "should return a valid access token" $ do
      actual <-
        generateDpopAccessToken
          proofExpiring2038
          uid
          clientId
          handle
          teamId
          domain
          nonce
          url
          method
          maxSkewSeconds
          expiration
          now
          pubKeyBundle
      pending
      isRight actual `shouldBe` True

    where
      pubKeyBundle =
            "-----BEGIN PRIVATE KEY-----\n\
            \MC4CAQAwBQYDK2VwBCIEIMkvahkqR9sHJSmFeCl3B7aJjsQGgwy++cccWTbuDyy+\n\
            \-----END PRIVATE KEY-----\n\
            \-----BEGIN PUBLIC KEY-----\n\
            \MCowBQYDK2VwAyEAdYI38UdxksC0K4Qx6E9JK9YfGm+ehnY18oKmHL2YsZk=\n\
            \-----END PUBLIC KEY-----\n"
      uid = fromMaybe (error "invalid user id") $ UUID.fromString "dbb07e94-7d29-4180-a790-a573def35dd5"
      proofExpiring2038 =
            "eyJhbGciOiJFZERTQSIsInR5cCI6ImRwb3Arand0IiwiandrIjp7Imt0eSI6Ik9LUCIsImNydiI6IkVkMjU1MTkiLCJ4IjoidUhNR0paWllUbU9zOEdiaTdaRUJLT255TnJYYnJzNTI1dE1QQUZoYjBzbyJ9fQ.eyJpYXQiOjE2Nzg4MDUyNTgsImV4cCI6MjA4ODc3MzI1OCwibmJmIjoxNjc4ODA1MjU4LCJzdWIiOiJpbTp3aXJlYXBwPVpHSmlNRGRsT1RRM1pESTVOREU0TUdFM09UQmhOVGN6WkdWbU16VmtaRFUvN2M2MzExYTFjNDNjMmJhNkB3aXJlLmNvbSIsImp0aSI6ImQyOWFkYTQ2LTBjMzYtNGNiMS05OTVlLWFlMWNiYTY5M2IzNCIsIm5vbmNlIjoiYzB0RWNtOUNUME00TXpKU04zRjRkMEZIV0V4TGIxUm5aMDQ1U3psSFduTSIsImh0bSI6IlBPU1QiLCJodHUiOiJodHRwczovL3dpcmUuZXhhbXBsZS5jb20vY2xpZW50cy84OTYzMDI3MDY5ODc3MTAzNTI2L2FjY2Vzcy10b2tlbiIsImNoYWwiOiJaa3hVV25GWU1HbHFUVVpVU1hnNFdHdHBOa3h1WWpWU09XRnlVRU5hVGxnIn0.8p0lvdOPjJ8ogjjLP6QtOo216qD9ujP7y9vSOhdYb-O8ikmW09N00gjCf0iGT-ZkxBT-LfDE3eQx27tWQ3JPBQ"

      clientId = 8963027069877103526
      domain = "wire.com"
      nonce = "c0tEcm9CT0M4MzJSN3F4d0FHWExLb1RnZ045SzlHWnM"
      url = "https://wire.example.com/clients/8963027069877103526/access-token"
      method = "POST"
      maxSkewSeconds = 5
      expiration = 2136351646
      now = 360
      handle = "horst"
      teamId = fromMaybe (error "invalid team id") $ UUID.fromString "d82c9fa1-b8c5-4023-82d6-cacee85e6a2b"

