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
      isRight actual `shouldBe` True
    where
      pubKeyBundle =
            "-----BEGIN PRIVATE KEY-----\n\
            \MC4CAQAwBQYDK2VwBCIEIMkvahkqR9sHJSmFeCl3B7aJjsQGgwy++cccWTbuDyy+\n\
            \-----END PRIVATE KEY-----\n\
            \-----BEGIN PUBLIC KEY-----\n\
            \MCowBQYDK2VwAyEAdYI38UdxksC0K4Qx6E9JK9YfGm+ehnY18oKmHL2YsZk=\n\
            \-----END PUBLIC KEY-----\n"
      uid = fromMaybe (error "invalid user id") $ UUID.fromString "b20b8c78-b26d-43a4-af24-f72a3cb6f606"
      proofExpiring2038 =
            "eyJhbGciOiJFZERTQSIsImp3ayI6eyJjcnYiOiJFZDI1NTE5Iiwia3R5IjoiT0tQIiwieCI6Im5MSkdOLU9hNkpzcTNLY2xaZ2dMbDdVdkFWZG1CMFE2QzNONUJDZ3BoSHcifSwidHlwIjoiZHBvcCtqd3QifQ.eyJjaGFsIjoid2EyVnJrQ3RXMXNhdUoyRDN1S1k4cmM3eTRrbDR1c0giLCJleHAiOjE4MzExMjYxNjMsImhhbmRsZSI6IndpcmVhcHA6Ly8lNDBwaHVoaGliZGhxYnF4cnpibnNhZndAZXhhbXBsZS5jb20iLCJodG0iOiJQT1NUIiwiaHR1IjoiaHR0cHM6Ly9leGFtcGxlLmNvbS9jbGllbnRzL2NjNmU2NDBlMjk2ZThiYmEvYWNjZXNzLXRva2VuIiwiaWF0IjoxNzA0OTgyMTYzLCJqdGkiOiI2ZmM1OWU3Zi1iNjY2LTRmZmMtYjczOC00ZjQ3NjBjODg0Y2EiLCJuYmYiOjE3MDQ5ODIxNjMsIm5vbmNlIjoiVnZHYnc2ZVZUTkdTUWJLNVNlaVNiQSIsInN1YiI6IndpcmVhcHA6Ly9zZ3VNZUxKdFE2U3ZKUGNxUExiMkJnIWNjNmU2NDBlMjk2ZThiYmFAZXhhbXBsZS5jb20iLCJ0ZWFtIjoiNDAyNTE2ODAtMzVlMS00Mzc0LWIzYWEtNzU2MDBkZTc5ZTMzIn0.JgVXD2_E4j4sLcvD284Fj4z_6xmwA0czcP8wzHZmqPpel60HUqDVKDx5GmiWbFWix-E7ZXvYfvZ7NmxlDrgmAg"

      clientId = 14730821443162901434
      domain = "example.com"
      nonce = "VvGbw6eVTNGSQbK5SeiSbA"
      url = "https://example.com/clients/cc6e640e296e8bba/access-token"
      method = "POST"
      maxSkewSeconds = 1
      expiration = 1831212562
      now = 1704982162
      handle = "phuhhibdhqbqxrzbnsafw"
      teamId = fromMaybe (error "invalid team id") $ UUID.fromString "40251680-35e1-4374-b3aa-75600de79e33"

