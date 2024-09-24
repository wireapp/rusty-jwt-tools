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
    clientId = 1223
    domain = "example.com"
    url = "https://wire.example.com/client/token"
    method = "POST"
    maxSkewSeconds = 1
    now = 1704982162
    proof = "eyJhbGciOiJFUzI1NiIsInR5cCI6ImRwb3Arand0IiwiandrIjp7Imt0eSI6IkVDIiwiY3J2IjoiUC0yNTYiLCJ4IjoiLUE2T3ZqNFVzRmFrbFZMUHZhZDhYNF80MXRBTW55ZnR3aGVXbnNSMzVvbyIsInkiOiI3S3E3UzQxUjh4NUVzTnVjY1J4Y3ItcjN2SWhYVmloR3BLUFAweThIczBvIn19.eyJpYXQiOjE3MjcyMTI5NDIsImV4cCI6MjA0MjU3NjU0MiwibmJmIjoxNzI3MjEyOTQyLCJzdWIiOiJ3aXJlYXBwOi8vU3ZQZkxsd0JRaS02b2RkVlJya3FwdyE0YzdAZXhhbXBsZS5jb20iLCJhdWQiOiJodHRwczovL3N0ZXBjYS9hY21lL3dpcmUvY2hhbGxlbmdlL2FhYS9iYmIiLCJqdGkiOiJlNzg1MGYxNy1jYzc3LTQ0ZmYtYThiNi0wODMyYjA1NTdkNmUiLCJub25jZSI6IldFODhFdk9CemJxR2Vyem5NKzJQL0FhZFZmNzM3NHkwY0gxOXNEU1pBMkEiLCJodG0iOiJQT1NUIiwiaHR1IjoiaHR0cHM6Ly93aXJlLmV4YW1wbGUuY29tL2NsaWVudC90b2tlbiIsImNoYWwiOiJva0FKMzNZbS9YUzJxbW1oaGg3YVdTYkJsWXk0VHRtMUV5c3FXOEkvOW5nIiwiaGFuZGxlIjoid2lyZWFwcDovLyU0MGpvaG5fZG9lQGV4YW1wbGUuY29tIiwidGVhbSI6IjZlODVlMDUzLTUzNmYtNDU4NS04ZmM4LWNhZGE4NzZlNWVjNyIsIm5hbWUiOiJKb2huIERvZSJ9.M7Zc0FIHazWbWg6PeFK1DVJoLiLeqx09Y9KQSLPgrp5DzGnvj2Gxo4z0ELwzpIUv9pfuw4f-tImRQSS7_RKmww"
    uid = fromMaybe (error "invalid user id") $ UUID.fromString "4af3df2e-5c01-422f-baa1-d75546b92aa7"
    nonce = "WE88EvOBzbqGerznM+2P/AadVf7374y0cH19sDSZA2A"
    expiration = 2042742401
    handle = "john_doe"
    displayName = "John Doe"
    teamId = fromMaybe (error "invalid team id") $ UUID.fromString "6e85e053-536f-4585-8fc8-cada876e5ec7"
