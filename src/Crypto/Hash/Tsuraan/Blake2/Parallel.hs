{-# LANGUAGE OverloadedStrings #-}
module Crypto.Hash.Tsuraan.Blake2.Parallel
( hash
, hashKey
) where

import Data.ByteString ( ByteString )
import System.IO.Unsafe ( unsafePerformIO )
import Foreign.C ( CInt(..) )
import Foreign.Ptr ( Ptr )
import Data.Word ( Word8 )

import Crypto.Hash.Tsuraan.Blake2.Internal ( runHasher )

foreign import ccall "blake2.h blake2bp" blake2bp
  :: Ptr Word8 -> Ptr Word8 -> Ptr Word8 -> Int -> Int -> Int -> IO CInt

-- |Hash a 'ByteString' into a digest 'ByteString' using a key. This function
-- always runs in parallel, which is slower for very small strings but faster
-- as the strings get larger.
hashKey :: ByteString -- ^The key to hash with
        -> Int        -- ^The digest size to generate; must be 1-64
        -> ByteString -- ^The string to hash
        -> ByteString
hashKey key hashlen bytes = unsafePerformIO $ runHasher blake2bp key hashlen bytes

-- |Hash a 'ByteString' into a digest 'ByteString'. This function always runs
-- in parallel, which is slower for very small strings but faster as the
-- strings get larger.
hash :: Int        -- ^The digest size to generate; must be 1-64
     -> ByteString -- ^The string to hash
     -> ByteString
hash = hashKey ""

