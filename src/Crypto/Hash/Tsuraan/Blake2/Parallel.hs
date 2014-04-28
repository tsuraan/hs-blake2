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

hashKey :: ByteString -> Int -> ByteString -> ByteString
hashKey key hashlen bytes = unsafePerformIO $ runHasher blake2bp key hashlen bytes

hash :: Int -> ByteString -> ByteString
hash = hashKey ""

