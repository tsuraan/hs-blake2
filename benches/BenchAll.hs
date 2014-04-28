{-# LANGUAGE OverloadedStrings #-}
module Main
( main
) where

import qualified Crypto.Hash.MD5 as MD5
import qualified Crypto.Hash.SHA1 as SHA1
import qualified Crypto.Hash.SHA256 as SHA2
import qualified Crypto.Hash.SHA3 as SHA3
import qualified Crypto.Hash.Skein256 as Skein
import qualified Crypto.Hash.Tiger as Tiger
import Data.ByteString ( hGetSome )
import System.IO
import Criterion.Main

import qualified Crypto.Hash.Tsuraan.Blake2.Parallel as ParBlake2
import qualified Crypto.Hash.Tsuraan.Blake2.Serial as SerBlake2
import qualified Crypto.Hash.Tsuraan.Blake2 as Blake2

main :: IO ()
main = do
  strings <- withFile "/dev/urandom" ReadMode $ \handle -> do
    -- let lens = [1000,2000,3000,4000,5000,6000,7000,8000,9000,10000]
    let lens = [1,10,100,1000,3000,6000,10000,30000,60000,100000]
    ss <- mapM (hGetSome handle) lens
    return $ zip lens ss
  defaultMain $
    [ bgroup (show sz)
             [ bench "Parallel" $ nf (ParBlake2.hash 32) st
             , bench "Sequential" $ nf (SerBlake2.hash 32) st
             , bench "Auto" $ nf (Blake2.hash 32) st
             , bench "MD5" $ nf MD5.hash st
             , bench "SHA1" $ nf SHA1.hash st
             , bench "SHA2" $ nf SHA2.hash st
             , bench "SHA3" $ nf (SHA3.hash 32) st
             , bench "Skein" $ nf (Skein.hash 32) st
             , bench "Tiger" $ nf Tiger.hash st
             ]
    | (sz, st) <- strings ]

