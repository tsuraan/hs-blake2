module Main
( main
) where

import qualified Data.ByteString as BS
import Data.ByteString.Arbitrary ( ArbByteString(..) )
import Data.ByteString ( ByteString )
import Control.Monad ( replicateM )

import qualified Crypto.Hash.Tsuraan.Blake2.Parallel as P
import qualified Crypto.Hash.Tsuraan.Blake2.Serial as S

import Test.QuickCheck
import Test.QuickCheck.Monadic
import Test.Tasty
import Test.Tasty.QuickCheck ( testProperty )

main :: IO ()
main = defaultMain $
  testGroup
    "Blake2"
    [ testGroup "Simple"
      [ testProperty "Parallel"
        $ update_equals_hash P.init P.update P.finalize P.hash
      , testProperty "Serial"
        $ update_equals_hash S.init S.update S.finalize S.hash
      ]
    , testGroup "Keyed"
      [ testProperty "Parallel"
        $ key_update_equals_hash P.init_key P.update P.finalize P.hash_key
      , testProperty "Serial"
        $ key_update_equals_hash S.init_key S.update S.finalize S.hash_key
      ]
    ]

update_equals_hash :: (Int -> IO a)
                   -> (a -> ByteString -> IO())
                   -> (a -> IO ByteString)
                   -> (Int -> ByteString -> ByteString)
                   -> Property
update_equals_hash ini upd fin hash = monadicIO $ do
  num  <- pick $ choose (1,20)
  strs <- replicateM num $ fromABS `fmap` pick arbitrary
  sz   <- pick $ choose (1,64)

  h <- run $ do
    ctx <- ini sz
    mapM_ (upd ctx) strs
    fin ctx
  assert $ h == hash sz (BS.concat strs)

key_update_equals_hash :: (ByteString -> Int -> IO a)
                       -> (a -> ByteString -> IO())
                       -> (a -> IO ByteString)
                       -> (ByteString -> Int -> ByteString -> ByteString)
                       -> Property
key_update_equals_hash ini upd fin hash = monadicIO $ do
  keylen <- pick $ choose (1,64)
  keyw8s <- replicateM keylen $ pick arbitrary
  num    <- pick $ choose (1,20)
  strs   <- replicateM num $ fromABS `fmap` pick arbitrary
  sz     <- pick $ choose (1,64)

  let key = BS.pack keyw8s
  h <- run $ do
    ctx <- ini key sz
    mapM_ (upd ctx) strs
    fin ctx
  assert $ h == hash key sz (BS.concat strs)

