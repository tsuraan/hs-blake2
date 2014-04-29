{-# LANGUAGE OverloadedStrings #-}
module Crypto.Hash.Tsuraan.Blake2.Serial
( Ctx
, init
, init_key
, update
, finalize
, hash
, hashKey
) where

import Data.ByteString ( ByteString )
import System.IO.Unsafe ( unsafePerformIO )
import Foreign.C ( CInt(..) )
import Foreign.Ptr ( Ptr )
import Foreign.Storable ( Storable(..) )
import Data.Word ( Word8 )

import Crypto.Hash.Tsuraan.Blake2.Internal ( BlakeState(..), runHasher, runInit, runInitKey, runUpdate, runFinalize )

import Prelude hiding ( init )

data Blake2bState

-- |Opaque type that tracks the Blake2 hashing state. The update and finalize
-- functions mutate this context.
newtype Ctx = Ctx (BlakeState Blake2bState) deriving ( Show )

instance Storable Blake2bState where
  sizeOf _    = unsafePerformIO blake2b_size
  alignment _ = 64 -- from blake2.h; this should be automagical, I think
  peek _      = error "no peek"
  poke _a _b  = error "no poke"

foreign import ccall "blake2.h blake2b" blake2b
  :: Ptr Word8 -> Ptr Word8 -> Ptr Word8 -> Int -> Int -> Int -> IO CInt

foreign import ccall "blake2.h blake2b_init" blake2b_init
  :: Ptr Blake2bState -> Int -> IO CInt

foreign import ccall "blake2.h blake2b_init_key" blake2b_init_key
  :: Ptr Blake2bState -> Int -> Ptr Word8 -> Int -> IO CInt

foreign import ccall "blake2.h blake2b_update" blake2b_update
  :: Ptr Blake2bState -> Ptr Word8 -> Int -> IO CInt

foreign import ccall "blake2.h blake2b_final" blake2b_final
  :: Ptr Blake2bState -> Ptr Word8 -> Int -> IO CInt

foreign import ccall "alloc.h blake2b_size" blake2b_size
  :: IO Int

-- |Create a hashing context.
init :: Int    -- ^Desired digest size
     -> IO Ctx
init outlen = Ctx `fmap` runInit blake2b_init outlen

-- |Create a hashing context for key-based hashing.
init_key :: ByteString  -- ^Desired hashing key
         -> Int         -- ^Desired digest size
         -> IO Ctx
init_key key outlen = Ctx `fmap` runInitKey blake2b_init_key key outlen

-- |Add more data to the hash.
update :: Ctx         -- ^Hashing context
       -> ByteString  -- ^Data to add to the hash
       -> IO ()
update (Ctx ptr) bs = runUpdate blake2b_update ptr bs

-- |Finish hashing. This returns the digest of all the data that's been given
-- to the 'update' function.
finalize :: Ctx           -- ^Hashing context
         -> IO ByteString
finalize (Ctx state) = runFinalize blake2b_final state

-- |Hash a 'ByteString' into a digest 'ByteString' using a key. This function
-- always runs in serial, which is faster for very small strings but slower as
-- the strings get larger.
hashKey :: ByteString -- ^The key to hash with
        -> Int        -- ^The digest size to generate; must be 1-64
        -> ByteString -- ^The string to hash
        -> ByteString
hashKey key hashlen bytes = runHasher blake2b key hashlen bytes

-- |Hash a 'ByteString' into a digest 'ByteString'. This function always runs
-- in serial, which is faster for very small strings but slower as the strings
-- get larger.
hash :: Int        -- ^The digest size to generate; must be 1-64
     -> ByteString -- ^The string to hash
     -> ByteString
hash = hashKey ""

