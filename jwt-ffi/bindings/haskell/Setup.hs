module Main (main) where

import Data.Maybe
import qualified Distribution.PackageDescription as PD
import Distribution.Simple
import Distribution.Simple.LocalBuildInfo
import Distribution.Simple.Setup
import System.Directory

main :: IO ()
main =
  defaultMainWithHooks
    simpleUserHooks {confHook = customConfHook}

customConfHook ::
  (PD.GenericPackageDescription, PD.HookedBuildInfo) ->
  ConfigFlags ->
  IO LocalBuildInfo
customConfHook (description, buildInfo) flags = do
  localBuildInfo <- confHook simpleUserHooks (description, buildInfo) flags
  let packageDescription = localPkgDescr localBuildInfo
      library = fromJust $ PD.library packageDescription
      libraryBuildInfo = PD.libBuildInfo library
  dir <- getCurrentDirectory
  pure
    localBuildInfo
      { localPkgDescr =
          packageDescription
            { PD.library =
                Just $
                  library
                    { PD.libBuildInfo =
                        libraryBuildInfo
                          { PD.extraLibDirs = (dir ++ "/target/debug") : PD.extraLibDirs libraryBuildInfo
                          }
                    }
            }
      }
