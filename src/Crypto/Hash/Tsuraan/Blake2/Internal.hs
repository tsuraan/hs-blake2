{-# LANGUAGE OverloadedStrings #-}
module Crypto.Hash.Tsuraan.Blake2.Internal
( BlakeState(..)
, runInit
, runInitKey
, runUpdate
, runFinalize
, runHasher
) where

import Data.ByteString.Internal ( create, toForeignPtr )
import Data.ByteString ( ByteString )
import System.IO.Unsafe ( unsafePerformIO )
import Foreign.ForeignPtr ( ForeignPtr, withForeignPtr, mallocForeignPtr )
import Foreign.Ptr ( Ptr, plusPtr )
import Foreign.C ( CInt(..) )
import Foreign.Storable ( Storable )
import Data.Word ( Word8 )

type BlakeHasher =
  Ptr Word8 -> Ptr Word8 -> Ptr Word8 -> Int -> Int -> Int -> IO CInt

data BlakeState a = BlakeState Int (ForeignPtr a) deriving ( Show )

runInit :: Storable a => (Ptr a -> Int -> IO CInt) -> Int -> IO (BlakeState a)
runInit ifn outlen = do
  fptr <- mallocForeignPtr
  withForeignPtr fptr $ \ptr -> do
    success <- ifn ptr outlen
    if success == 0
      then return $ BlakeState outlen fptr
      else error "runInit failure; probably a bad digest size"

runInitKey :: Storable a => (Ptr a -> Int -> Ptr Word8 -> Int -> IO CInt)
           -> ByteString -> Int -> IO (BlakeState a)
runInitKey ifn key outlen =
  let (kforeignptr, koff, klen) = toForeignPtr key
  in withForeignPtr kforeignptr $ \kptr -> do
      fptr <- mallocForeignPtr
      withForeignPtr fptr $ \ptr -> do
        success <- ifn ptr outlen (kptr `plusPtr` koff) klen
        if success == 0
          then return $ BlakeState outlen fptr
          else error "runInit failure; bad digest size or bad key size"

runUpdate :: (Ptr a -> Ptr Word8 -> Int -> IO CInt)
          -> BlakeState a -> ByteString -> IO ()
runUpdate ufn (BlakeState _ ctx) string =
  let (sforeignptr, soff, slen) = toForeignPtr string
  in withForeignPtr sforeignptr $ \sptr ->
      withForeignPtr ctx $ \cptr -> do
        _ <- ufn cptr (sptr `plusPtr` soff) slen
        return ()

runFinalize :: (Ptr a -> Ptr Word8 -> Int -> IO CInt)
            -> BlakeState a -> IO ByteString
runFinalize ffn (BlakeState hashlen fptr) =
  create hashlen $ \hptr ->
    withForeignPtr fptr $ \ctx -> do
      _ <- ffn ctx hptr hashlen
      return ()

runHasher :: BlakeHasher -> ByteString -> Int -> ByteString -> ByteString
runHasher hasher key hashlen bytes = unsafePerformIO $ create hashlen $ \hptr ->
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

