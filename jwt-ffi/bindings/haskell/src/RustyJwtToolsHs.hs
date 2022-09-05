module RustyJwtToolsHs where

import Control.Exception
import Control.Monad.IO.Class
import Data.ByteString (ByteString)
import Data.Maybe ()
import Data.String.Conversions (cs)
import Data.Text
import Data.UUID
import Data.Word (Word32, Word64, Word8)
import Foreign.C.String (CString, newCString, peekCString)
import Foreign.Ptr (nullPtr)
import Text.Read (readMaybe)
import Prelude

foreign import ccall unsafe "generate_dpop_access_token"
  generate_dpop_access_token ::
    CString ->
    CString ->
    Word32 ->
    CString ->
    CString ->
    CString ->
    CString ->
    Word32 ->
    Word64 ->
    Word64 ->
    CString ->
    IO CString

foreign import ccall unsafe "free_dpop_access_token" free_dpop_access_token :: CString -> IO ()

generateDpopAccessToken ::
  (MonadIO m) =>
  ByteString ->
  UUID ->
  Word32 ->
  Text ->
  ByteString ->
  Text ->
  Text ->
  Word32 ->
  Word64 ->
  Word64 ->
  ByteString ->
  m (Either String ByteString)
generateDpopAccessToken dpopProof user client domain nonce uri method maxSkewSecs expiration now backendKeys = do
  let getToken = do
        dpopProofCStr <- newCString (cs dpopProof)
        userCStr <- newCString (cs (toText user))
        domainCStr <- newCString (cs domain)
        nonceCStr <- newCString (cs nonce)
        uriCStr <- newCString (cs uri)
        methodCStr <- newCString (cs method)
        backendKeysCStr <- newCString (cs backendKeys)
        generate_dpop_access_token
          dpopProofCStr
          userCStr
          client
          domainCStr
          nonceCStr
          uriCStr
          methodCStr
          maxSkewSecs
          expiration
          now
          backendKeysCStr

  let fromCStrToBs ptr = do
        if ptr /= nullPtr
          then do
            dpopAccessToken <- peekCString ptr
            pure $ validateResponse dpopAccessToken
          else pure $ Left "pointer is null"

  liftIO $ bracket getToken free_dpop_access_token fromCStrToBs
  where
    validateResponse :: String -> Either String ByteString
    validateResponse r =
      maybe (pure $ cs r) (const $ Left r) (readMaybe @Word8 r)
