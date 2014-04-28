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

hashKey :: ByteString -> Int -> ByteString -> ByteString
hashKey key hashlen bytes = unsafePerformIO $ runHasher blake2b key hashlen bytes

hash :: Int -> ByteString -> ByteString
hash = hashKey ""

