module RustyJwtToolsHs where

import Data.Maybe ()
import Foreign.C.Types ( CLong(..) )
import Foreign.Ptr (nullPtr, Ptr)
import Foreign.C.String (CString(..), peekCString)
import Data.Data (Typeable)
import Control.Exception ( Exception, throw )
import Data.Word (Word64, Word32)

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

data FfiException
  = NullPointerError
  deriving (Show,Typeable)

instance Exception FfiException

generateDpopAccessToken ::
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
    IO String
generateDpopAccessToken dpopProof user client domain nonce uri method maxSkewSecs expiration now backendKeys = do
  ptr <- generate_dpop_access_token dpopProof user client domain nonce uri method maxSkewSecs expiration now backendKeys
  if ptr /= nullPtr
    then do
      dpopAccessToken <- peekCString ptr
      free_dpop_access_token ptr
      return dpopAccessToken
    else
      throw NullPointerError
