{-# LANGUAGE OverloadedStrings #-}
module Crypto.Hash.Tsuraan.Blake2
( hash
, hashKey
) where

import Data.ByteString ( ByteString, length )
import Prelude hiding ( length )

import qualified Crypto.Hash.Tsuraan.Blake2.Parallel as Par
import qualified Crypto.Hash.Tsuraan.Blake2.Serial as Ser

hashKey :: ByteString -> Int -> ByteString -> ByteString
hashKey key hashlen bytes =
  if length bytes < cutoff
    then Ser.hashKey key hashlen bytes
    else Par.hashKey key hashlen bytes

hash :: Int -> ByteString -> ByteString
hash hashlen bytes =
  if length bytes < cutoff
    then Ser.hash hashlen bytes
    else Par.hash hashlen bytes

-- This is a fairly sane cross-over point for when a hash is faster to
-- calculate in parallel than serially. This was found through experimentation,
-- so there's probably a smarter way to deal with it.
cutoff :: Int
cutoff = 5000

