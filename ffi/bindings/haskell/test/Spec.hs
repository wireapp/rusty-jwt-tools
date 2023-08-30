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
            \MC4CAQAwBQYDK2VwBCIEIMkvahkqR9sHJSmFeCl3B7aJjsQGgwy++cccWTbuDyy+\n\
            \-----END PRIVATE KEY-----\n\
            \-----BEGIN PUBLIC KEY-----\n\
            \MCowBQYDK2VwAyEAdYI38UdxksC0K4Qx6E9JK9YfGm+ehnY18oKmHL2YsZk=\n\
            \-----END PUBLIC KEY-----\n"
      uid = fromMaybe (error "invalid user id") $ UUID.fromString "83a23b74-69c6-4bd5-931c-1c6406a832c2"
      proofExpiring2038 =
            "eyJhbGciOiJFZERTQSIsInR5cCI6ImRwb3Arand0IiwiandrIjp7Imt0eSI6Ik9LUCIsImNydiI6IkVkMjU1MTkiLCJ4Ijoick5GRFBEdEdsakZpbElYUFpfMlpUR0tfaVNqT2hrcjlXQXFNbGxtSm1WNCJ9fQ.eyJpYXQiOjE2OTMzODQ5ODcsImV4cCI6MTY5MzQ3MTM4NywibmJmIjoxNjkzMzg0OTgyLCJzdWIiOiJpbTp3aXJlYXBwPWc2STdkR25HUzlXVEhCeGtCcWd5d2cvYTU4ZjU1NjMyMmI5MDVjOEB3aXJlLmNvbSIsImp0aSI6IjUxYzFkNDUxLTM3NDktNDI1MC05ZGNjLTUzNzg5YTljNzY5MiIsIm5vbmNlIjoiT1RoaGVuazVkR3BuU0VwWllqQnFTR1ZzWjNWR1pESmljVzlMTUVacmRuTSIsImh0bSI6IlBPU1QiLCJodHUiOiJodHRwczovL3dpcmUuZXhhbXBsZS5jb20vY2xpZW50cy8xMTkyOTg0NzgyMjIwMDQwNzQ5Ni9hY2Nlc3MtdG9rZW4iLCJjaGFsIjoiVkVoa00xa3lSa015UlhoTk9ITmtiR3hNT0cwMmNuWmhkVGRLVVZWNFFYQSJ9.Q7IyWSGtKCM0UFxETriUH6vN9yNCa44erZiNHapBcQ6q1wVEFMxYZbN5DdWE3lxJTg7oQbVZnQcLErKv3CWlCQ"

      clientId = 11929847822200407496
      domain = "wire.com"
      nonce = "OThhenk5dGpnSEpZYjBqSGVsZ3VGZDJicW9LMEZrdnM"
      url = "https://wire.example.com/clients/11929847822200407496/access-token"
      method = "POST"
      maxSkewSeconds = 5
      expiration = 2136351646
      now = 360
