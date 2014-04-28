{-# LANGUAGE OverloadedStrings #-}
module Crypto.Hash.Tsuraan.Blake2
( hash
, hashKey
) where

import Data.ByteString ( ByteString, length )
import Prelude hiding ( length )

import qualified Crypto.Hash.Tsuraan.Blake2.Parallel as Par
import qualified Crypto.Hash.Tsuraan.Blake2.Serial as Ser

-- | Hash a strict 'ByteString' into a digest 'ByteString' using a key. This
-- will choose to use parallel or serial Blake2 depending on the size of the
-- input 'ByteString'.
hashKey :: ByteString -- ^The key to use when hashing
        -> Int        -- ^The digest size to generate; must be 1-64
        -> ByteString -- ^The 'ByteString' to hash
        -> ByteString
hashKey key hashlen bytes =
  if length bytes < cutoff
    then Ser.hashKey key hashlen bytes
    else Par.hashKey key hashlen bytes

-- | Hash a strict 'ByteString' into a digest 'ByteString'. This will choose to
-- use parallel or serial Blake2 depending on the size of the input
-- 'ByteString'
hash :: Int        -- ^The digest size to generate; must be 1-64
     -> ByteString -- ^The 'ByteString' to hash
     -> ByteString
hash hashlen bytes =
  if length bytes < cutoff
    then Ser.hash hashlen bytes
    else Par.hash hashlen bytes

-- This is a fairly sane cross-over point for when a hash is faster to
-- calculate in parallel than serially. This was found through experimentation,
-- so there's probably a smarter way to deal with it.
cutoff :: Int
cutoff = 5000

