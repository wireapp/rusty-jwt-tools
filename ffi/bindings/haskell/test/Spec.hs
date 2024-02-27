{-# OPTIONS_GHC -Wno-incomplete-uni-patterns #-}

import Data.Either
import Data.Maybe
import Data.UUID as UUID
import RustyJwtToolsHs
import Test.Hspec
import Prelude

main :: IO ()
main = hspec $ do
  describe "generate_dpop_access_token" $ do
    it "should return an error when given wrong nonce" $ do
      actual <-
        generateDpopAccessToken
          proof
          uid
          clientId
          handle
          displayName
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
          proof
          uid
          clientId
          handle
          displayName
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
    pubKeyBundle = "-----BEGIN PRIVATE KEY-----\n\
                   \MIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQg5i88D4XpjBudqAkS\n\
                   \3r4zMK0hEXT7i+xR3PyGfrPHcqahRANCAAQ84mdGFohHioIhOG/s8S2mHNXiKzdV\n\
                   \ZTvpq663q4ErPGj7OP0P7Ef1QrXvHmTDOTx5YwUJ3OAxDXDOdSkD0zPt\n\
                   \-----END PRIVATE KEY-----"
    clientId = 14730821443162901434
    domain = "example.com"
    url = "https://example.com/clients/cc6e640e296e8bba/access-token"
    method = "POST"
    maxSkewSeconds = 1
    now = 1704982162

    proof = "eyJhbGciOiJFUzI1NiIsInR5cCI6ImRwb3Arand0IiwiandrIjp7Imt0eSI6IkVDIiwiY3J2IjoiUC0yNTYiLCJ4IjoiUE9KblJoYUlSNHFDSVRodjdQRXRwaHpWNGlzM1ZXVTc2YXV1dDZ1Qkt6dyIsInkiOiJhUHM0X1Ffc1JfVkN0ZThlWk1NNVBIbGpCUW5jNERFTmNNNTFLUVBUTS0wIn19.eyJpYXQiOjE3MjU5NTY1MjUsImV4cCI6MTcyNjA0NjUyNSwibmJmIjoxNzI1OTU2NTI1LCJzdWIiOiJ3aXJlYXBwOi8vTkdyekQ2T0NRYmlwdWpHOS1UVXU2dyFjYzZlNjQwZTI5NmU4YmJhQGV4YW1wbGUuY29tIiwiYXVkIjoiaHR0cHM6Ly9zdGVwY2EvYWNtZS93aXJlL2NoYWxsZW5nZS9hYWEvYmJiIiwianRpIjoiMmQwNDMyOTMtNDg5My00NDU3LTk4NTAtZGUwOGQ0NDg2Njg2Iiwibm9uY2UiOiI0M0ZDSWMwVVFqaU5tdlBPSHoyenl3IiwiaHRtIjoiUE9TVCIsImh0dSI6Imh0dHBzOi8vZXhhbXBsZS5jb20vY2xpZW50cy9jYzZlNjQwZTI5NmU4YmJhL2FjY2Vzcy10b2tlbiIsImNoYWwiOiI0M0ZDSWMwVVFqaU5tdlBPSHoyenl3IiwiaGFuZGxlIjoid2lyZWFwcDovLyU0MGtjdmVwY2tieWZ5eWV4anNwc3pjeEBleGFtcGxlLmNvbSIsInRlYW0iOiI2ZTg1ZTA1My01MzZmLTQ1ODUtOGZjOC1jYWRhODc2ZTVlYzciLCJuYW1lIjoiam9lIn0.YJydGqugbKKq_IBdphLVVwJmyEg2ESItEZtqZu6AWprl5KFSZo7knbRDw2AGSREobBFElis8uaHqXo18w5htkg"
    uid = fromMaybe (error "invalid user id") $ UUID.fromString "346af30f-a382-41b8-a9ba-31bdf9352eeb"
    nonce = "43FCIc0UQjiNmvPOHz2zyw"
    expiration = 1881935509
    handle = "kcvepckbyfyyexjspszcx"
    displayName = "joe"
    teamId = fromMaybe (error "invalid team id") $ UUID.fromString "6e85e053-536f-4585-8fc8-cada876e5ec7"
