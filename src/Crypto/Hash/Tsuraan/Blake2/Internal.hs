{-# LANGUAGE OverloadedStrings #-}
module Crypto.Hash.Tsuraan.Blake2.Internal
( runHasher
) where

import Data.ByteString.Internal ( create, toForeignPtr )
import Data.ByteString ( ByteString )
import Foreign.ForeignPtr ( withForeignPtr )
import Foreign.Ptr ( Ptr, plusPtr )
import Foreign.C ( CInt(..) )
import Data.Word ( Word8 )

type BlakeHasher =
  Ptr Word8 -> Ptr Word8 -> Ptr Word8 -> Int -> Int -> Int -> IO CInt

runHasher :: BlakeHasher -> ByteString -> Int -> ByteString -> IO ByteString
runHasher hasher key hashlen bytes = create hashlen $ \hptr ->
  let (kforeignptr, koff, klen) = toForeignPtr key
      (bforeignptr, boff, blen) = toForeignPtr bytes
  in withForeignPtr kforeignptr $ \kptr ->
      withForeignPtr bforeignptr $ \bptr -> do
        result <- hasher hptr (bptr `plusPtr` boff) (kptr `plusPtr` koff)
                         hashlen blen klen
        if result /= 0
          then error "Blake2bp Error: probably bad key length or hash length"
          else return ()

-- Inline here gives us a ~15% speedup on ghc 7.8.2
{-# INLINE runHasher #-}

