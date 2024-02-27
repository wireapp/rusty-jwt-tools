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
          proofExpiring2038
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
          proofExpiring2038
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
    pubKeyBundle =
      "-----BEGIN PRIVATE KEY-----\n\
      \MC4CAQAwBQYDK2VwBCIEIMkvahkqR9sHJSmFeCl3B7aJjsQGgwy++cccWTbuDyy+\n\
      \-----END PRIVATE KEY-----\n\
      \-----BEGIN PUBLIC KEY-----\n\
      \MCowBQYDK2VwAyEAdYI38UdxksC0K4Qx6E9JK9YfGm+ehnY18oKmHL2YsZk=\n\
      \-----END PUBLIC KEY-----\n"
    uid = fromMaybe (error "invalid user id") $ UUID.fromString "21fb56d0-ac54-4686-ae01-e86b0e4cdb6c"
    proofExpiring2038 =
      "eyJhbGciOiJFZERTQSIsImp3ayI6eyJjcnYiOiJFZDI1NTE5Iiwia3R5IjoiT0tQIiwieCI6Im5MSkdOLU9hNkpzcTNLY2xaZ2dMbDdVdkFWZG1CMFE2QzNONUJDZ3BoSHcifSwidHlwIjoiZHBvcCtqd3QifQ.eyJhdWQiOiJodHRwczovL3dpcmUuY29tL2FjbWUvY2hhbGxlbmdlL2FiY2QiLCJjaGFsIjoid2EyVnJrQ3RXMXNhdUoyRDN1S1k4cmM3eTRrbDR1c0giLCJleHAiOjE3Mzk4ODA2NzQsImhhbmRsZSI6IndpcmVhcHA6Ly8lNDB5d2Z5ZG5pZ2Jud2h1b3pldGphZ3FAZXhhbXBsZS5jb20iLCJodG0iOiJQT1NUIiwiaHR1IjoiaHR0cHM6Ly9leGFtcGxlLmNvbS9jbGllbnRzL2NjNmU2NDBlMjk2ZThiYmEvYWNjZXNzLXRva2VuIiwiaWF0IjoxNzA4MzQ0Njc0LCJqdGkiOiI2ZmM1OWU3Zi1iNjY2LTRmZmMtYjczOC00ZjQ3NjBjODg0Y2EiLCJuYW1lIjoi5reB4qqu5KSq5rK255Kh4bKV6re14Y2q6omE6Jy16Iu17ICV54Kb66-v56qp5KqW766M6bGw6oOy6b6m57m15pWJ4LqH54et6rOj54KHIiwibmJmIjoxNzA4MzQ0Njc0LCJub25jZSI6IllWZ2dHdWlTUTZlamhQNTNFX0tPS3ciLCJzdWIiOiJ3aXJlYXBwOi8vSWZ0VzBLeFVSb2F1QWVockRremJiQSFjYzZlNjQwZTI5NmU4YmJhQGV4YW1wbGUuY29tIiwidGVhbSI6ImMxNTE5NzVlLWIxOTMtNDAwOS1hM2QyLTc0N2M5NjFmMjMzMyJ9.SHxpMzOe2yC3y6DP7lEH0l7_eOKrUZZI0OjgtnCKjO4OBD0XqKOi0y_z07-7FWc-KtThlsaZatnBNTB67GhQBw"

    clientId = 14730821443162901434
    domain = "example.com"
    nonce = "YVggGuiSQ6ejhP53E_KOKw"
    url = "https://example.com/clients/cc6e640e296e8bba/access-token"
    method = "POST"
    maxSkewSeconds = 1
    expiration = 1739967074
    now = 1704982162
    handle = "ywfydnigbnwhuozetjagq"
    teamId = fromMaybe (error "invalid team id") $ UUID.fromString "c151975e-b193-4009-a3d2-747c961f2333"
    displayName = "\230\183\129\226\170\174\228\164\170\230\178\182\231\146\161\225\178\149\234\183\181\225\141\170\234\137\132\232\156\181\232\139\181\236\128\149\231\130\155\235\175\175\231\170\169\228\170\150\239\174\140\233\177\176\234\131\178\233\190\166\231\185\181\230\149\137\224\186\135\231\135\173\234\179\163\231\130\135"
