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
import Foreign.Ptr (Ptr, nullPtr)
import Prelude

data JwtResponse = JwtResponse

foreign import ccall unsafe "generate_dpop_access_token"
  generate_dpop_access_token ::
    CString ->
    CString ->
    Word64 ->
    CString ->
    CString ->
    CString ->
    CString ->
    Word32 ->
    Word64 ->
    Word64 ->
    CString ->
    IO (Ptr JwtResponse)

foreign import ccall unsafe "free_dpop_access_token" free_dpop_access_token :: Ptr JwtResponse -> IO ()

foreign import ccall unsafe "get_error" get_error :: Ptr JwtResponse -> Word8

foreign import ccall unsafe "get_token" get_token :: Ptr JwtResponse -> CString

createToken ::
  CString ->
  CString ->
  Word64 ->
  CString ->
  CString ->
  CString ->
  CString ->
  Word32 ->
  Word64 ->
  Word64 ->
  CString ->
  IO (Maybe (Ptr JwtResponse))
createToken dpopProof user client domain nonce uri method maxSkewSecs expiration now backendKeys = do
  ptr <- generate_dpop_access_token dpopProof user client domain nonce uri method maxSkewSecs expiration now backendKeys
  if ptr /= nullPtr
    then pure $ Just ptr
    else pure Nothing

getError :: Ptr JwtResponse -> IO (Maybe Word8)
getError ptr = do
  let e = get_error ptr
  if e /= 0
    then pure $ Just e
    else pure Nothing

getToken :: Ptr JwtResponse -> IO (Maybe String)
getToken ptr = do
  let tokenPtr = get_token ptr
  if tokenPtr /= nullPtr
    then Just <$> peekCString tokenPtr
    else pure Nothing

generateDpopAccessToken ::
  (MonadIO m) =>
  ByteString ->
  UUID ->
  Word64 ->
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
  let before = do
        dpopProofCStr <- newCString (cs dpopProof)
        userCStr <- newCString (cs (toText user))
        domainCStr <- newCString (cs domain)
        nonceCStr <- newCString (cs nonce)
        uriCStr <- newCString (cs uri)
        methodCStr <- newCString (cs method)
        backendKeysCStr <- newCString (cs backendKeys)
        createToken
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
  let thing response =
        case response of
          Nothing -> pure $ Left "Unable to create token"
          Just r -> do
            mErr <- getError r
            mToken <- getToken r
            pure $ toResult mErr mToken
  let after = maybe (pure ()) free_dpop_access_token
  liftIO $ bracket before after thing
  where
    toResult :: Maybe Word8 -> Maybe String -> Either String ByteString
    toResult _ (Just token) = Right $ cs token
    toResult (Just err) _ = Left $ "Error: " <> show err
    toResult _ _ = Left "Unable to create token"
