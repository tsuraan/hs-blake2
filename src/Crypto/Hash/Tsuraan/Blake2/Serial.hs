{-# LANGUAGE OverloadedStrings #-}
module Crypto.Hash.Tsuraan.Blake2.Serial
( hash
, hashKey
) where

import Data.ByteString ( ByteString )
import System.IO.Unsafe ( unsafePerformIO )
import Foreign.C ( CInt(..) )
import Foreign.Ptr ( Ptr )
import Data.Word ( Word8 )

import Crypto.Hash.Tsuraan.Blake2.Internal ( runHasher )

foreign import ccall "blake2.h blake2b" blake2b
  :: Ptr Word8 -> Ptr Word8 -> Ptr Word8 -> Int -> Int -> Int -> IO CInt

-- |Hash a 'ByteString' into a digest 'ByteString' using a key. This function
-- always runs in serial, which is faster for very small strings but slower as
-- the strings get larger.
hashKey :: ByteString -- ^The key to hash with
        -> Int        -- ^The digest size to generate; must be 1-64
        -> ByteString -- ^The string to hash
        -> ByteString
hashKey key hashlen bytes = unsafePerformIO $ runHasher blake2b key hashlen bytes

-- |Hash a 'ByteString' into a digest 'ByteString'. This function always runs
-- in serial, which is faster for very small strings but slower as the strings
-- get larger.
hash :: Int        -- ^The digest size to generate; must be 1-64
     -> ByteString -- ^The string to hash
     -> ByteString
hash = hashKey ""

