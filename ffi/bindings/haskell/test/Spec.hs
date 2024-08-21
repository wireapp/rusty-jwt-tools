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
      putStrLn "=================================="
      print actual
      putStrLn "=================================="
      isRight actual `shouldBe` True
  where
    pubKeyBundle =
      "-----BEGIN PRIVATE KEY-----\n\
      \MC4CAQAwBQYDK2VwBCIEIMkvahkqR9sHJSmFeCl3B7aJjsQGgwy++cccWTbuDyy+\n\
      \-----END PRIVATE KEY-----\n\
      \-----BEGIN PUBLIC KEY-----\n\
      \MCowBQYDK2VwAyEAdYI38UdxksC0K4Qx6E9JK9YfGm+ehnY18oKmHL2YsZk=\n\
      \-----END PUBLIC KEY-----\n"

    clientId = 14730821443162901434
    domain = "example.com"
    url = "https://example.com/clients/cc6e640e296e8bba/access-token"
    method = "POST"
    maxSkewSeconds = 1
    now = 1704982162

    proof = "eyJhbGciOiJFUzI1NiIsImp3ayI6eyJhbGciOiJFUzI1NiIsImNydiI6IlAtMjU2Iiwia3R5IjoiRUMiLCJ4IjoiaGNZamxvTm9keUNMRl9yUWRfSElzelNwYTJKLXZ6cmdudG5lQUpXNXBBOCIsInkiOiI2TVh4bkhxMUZtQVdDYzZBN1lWYWx4dmVraWNCdjUzQVJUUU8zNW1SS0o4In0sInR5cCI6ImRwb3Arand0In0.eyJhdWQiOiJodHRwczovL3dpcmUuY29tL2FjbWUvY2hhbGxlbmdlL2FiY2QiLCJjaGFsIjoid2EyVnJrQ3RXMXNhdUoyRDN1S1k4cmM3eTRrbDR1c0giLCJleHAiOjE4ODE5MzQ1MDksImhhbmRsZSI6IndpcmVhcHA6Ly8lNDBrY3ZlcGNrYnlmeXlleGpzcHN6Y3hAZXhhbXBsZS5jb20iLCJodG0iOiJQT1NUIiwiaHR1IjoiaHR0cHM6Ly9leGFtcGxlLmNvbS9jbGllbnRzL2NjNmU2NDBlMjk2ZThiYmEvYWNjZXNzLXRva2VuIiwiaWF0IjoxNzI0MjU0NTA5LCJqdGkiOiI2ZmM1OWU3Zi1iNjY2LTRmZmMtYjczOC00ZjQ3NjBjODg0Y2EiLCJuYW1lIjoiam9lIiwibmJmIjoxNzI0MjU0NTA5LCJub25jZSI6IjQzRkNJYzBVUWppTm12UE9IejJ6eXciLCJzdWIiOiJ3aXJlYXBwOi8vTkdyekQ2T0NRYmlwdWpHOS1UVXU2dyFjYzZlNjQwZTI5NmU4YmJhQGV4YW1wbGUuY29tIiwidGVhbSI6IjZlODVlMDUzLTUzNmYtNDU4NS04ZmM4LWNhZGE4NzZlNWVjNyJ9.Wgycwinkv5JAc9qZeV59FjpJyAaBmentDrGWAyDkpJI3IZo1Eob_chTVnPrGMjaIm1Wr3wd9azdWsIs_8H41cA"
    uid = fromMaybe (error "invalid user id") $ UUID.fromString "346af30f-a382-41b8-a9ba-31bdf9352eeb"
    nonce = "43FCIc0UQjiNmvPOHz2zyw"
    expiration = 1881935509
    handle = "kcvepckbyfyyexjspszcx"
    displayName = "joe"
    teamId = fromMaybe (error "invalid team id") $ UUID.fromString "6e85e053-536f-4585-8fc8-cada876e5ec7"
