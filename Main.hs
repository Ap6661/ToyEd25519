-- https://datatracker.ietf.org/doc/html/rfc8032#section-5.1.6
-- https://datatracker.ietf.org/doc/html/rfc7748
-- https://github.com/floodyberry/supercop/blob/master/crypto_sign/ed25519
-- https://github.com/openssh/openssh-portable/blob/master/ed25519.c



-- Doing the actual math is slow and computationally expensive. 
-- Lets cheat and use a list of coordinates
import Eddata

import Text.Hex as TH (decodeHex, encodeHex)
import Data.Text
import Data.Bits
import Sel.Hashing.SHA512 qualified as SHA512
import Data.ByteString as BS
import Data.Word (Word8, Word32)
import System.IO
import qualified Data.String as DS


newtype Fe25519 = Fe25519 [Word32]
   deriving (Show, Eq)

newtype Sc25519 = Sc25519 [Word32]
   deriving (Show, Eq)

data Ge25519 = Ge25519 {
  geX :: Fe25519,
  geY :: Fe25519,
  geZ :: Fe25519,
  geT :: Fe25519
}
   deriving (Show, Eq)

ge25519_ec2d = Fe25519 [0x59, 0xF1, 0xB2, 0x26, 0x94, 0x9B, 0xD6, 0xEB, 0x56, 0xB1, 0x83, 0x82, 0x9A, 0x14, 0xE0, 0x00, 0x30, 0xD1, 0xF3, 0xEE, 0xF2, 0x80, 0x8E, 0x19, 0xE7, 0xFC, 0xDF, 0x56, 0xDC, 0xD9, 0x06, 0x24]

mu :: [Word32]
mu = [0x1B, 0x13, 0x2C, 0x0A, 0xA3, 0xE5, 0x9C, 0xED, 0xA7, 0x29, 0x63, 0x08, 0x5D, 0x21, 0x06, 0x21,
       0xEB, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0x0F]

m :: [Word32]
m = [0xED, 0xD3, 0xF5, 0x5C, 0x1A, 0x63, 0x12, 0x58, 0xD6, 0x9C, 0xF7, 0xA2, 0xDE, 0xF9, 0xDE, 0x14,
  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x10]


prunedigest :: [Word8] -> [Word8]
prunedigest = rplf (64.|.) 31 . rplf (127.&.) 31 . rplf (248.&.) 0
  where
    rplf f i l = [ if i == n then f x else x | (n,x) <- Prelude.zip [0..] l ]

generatePublicKey = ge25519Pack . ge25519ScalarbaseMult . sc25519from32Bytes . prunedigest . BS.unpack . SHA512.hashToBinary



-- Message + SecretKey
sign m sk = (\r -> (r ++) <$> sout) =<< bigR
  where
    (fsk, prefix) = BS.splitAt 32 sk
    h =  SHA512.hashByteString fsk

    -- az: 32-byte scalar a, 32-byte randomizer z 
    az =  prunedigest . BS.unpack . SHA512.hashToBinary <$> h
    azt = Prelude.splitAt 32 <$> az
    a = fst <$> azt
    z = snd <$> azt
    bigA = generatePublicKey <$> h

    -- Nonce: r
    r = sc25519from64Bytes . BS.unpack . SHA512.hashToBinary <$>
        (SHA512.hashByteString . BS.pack . (++ m) =<< z)

    bigR = ge25519Pack . ge25519ScalarbaseMult <$> r

    -- h(RAm)
    ram = (\m -> (\a -> (\rr -> rr ++ a ++ m) <$> bigR) =<< bigA) m
    hRAm = SHA512.hashByteString . BS.pack =<< ram

    k = sc25519from64Bytes . BS.unpack . SHA512.hashToBinary <$> hRAm


    -- S = (r + k * s) mod L 
    ks = (\k -> sc25519Mul k <$> (sc25519from32Bytes <$> a)) =<< k

    bigS = (\r -> sc25519Add r <$> ks) =<< r

    sout = sc25519to32Bytes <$> bigS

sc25519from32Bytes :: [Word8] -> Sc25519
sc25519from32Bytes x = barretReduce $ (fromIntegral <$> Prelude.take 32 x) ++ Prelude.replicate 32 0

sc25519from64Bytes :: [Word8] -> Sc25519
sc25519from64Bytes x = barretReduce $ fromIntegral <$> x

sc25519to32Bytes :: Sc25519 -> [Word8]
sc25519to32Bytes (Sc25519 x) = Prelude.take 32 $ fromIntegral <$> x

bBStoDecimal :: IO ByteString -> IO Integer
bBStoDecimal bs = (Prelude.foldl (\x y -> x `shiftL` 8 + y) 0 <$> fmap fromIntegral) . BS.unpack <$> bs


chooseT pos b = Ge25519Aff { x = xx, y = y t }
  where
  (Fe25519 xx) = cmov tx (fe25519Neg tx) (negative b)
  tx = Fe25519 $ x t
  t :: Ge25519Aff
  t
    | 1 == geequal b 1 || 1 == geequal b (-1) = Eddata.base_mul_affine !! (5 * pos + 1)
    | 1 == geequal b 2 || 1 == geequal b (-2) = Eddata.base_mul_affine !! (5 * pos + 2)
    | 1 == geequal b 3 || 1 == geequal b (-3) = Eddata.base_mul_affine !! (5 * pos + 3)
    | 1 == geequal b (-4) = Eddata.base_mul_affine !! (5 * pos + 4)
    | otherwise = Eddata.base_mul_affine !! (5 * pos + 0)


setone = 1 : [0 | x <- [1..31]]

setzero :: Fe25519
setzero = Fe25519 [0 | x <- [0..31]]


fe25519Mul :: Fe25519 -> Fe25519 -> Fe25519
fe25519Mul (Fe25519 x) (Fe25519 y) = reduceMul $
    Fe25519 $
      [(tst !! x) + times38 (tnd !! x) | x <- [0..30]]
      ++
      [tst !! 31]
  where
  (tst, tnd) = Prelude.splitAt 32 $
    [sum [(x !! i) * (y !! j) |
      i <- [0..31],
      j <- [0..31],
      i+j == pos] |
    pos <- [0..63]]

reduceMul :: Fe25519 -> Fe25519
reduceMul r = rep $ rep r
  where
  rep :: Fe25519 -> Fe25519
  rep (Fe25519 r) = rest (
    Fe25519 (

    times19 (shiftR (Prelude.last r) 7) + Prelude.head r
    :
    Prelude.init (Prelude.tail r) ++ [127 .&. Prelude.last r]
    )) [0..30]

  rest :: Fe25519 -> [Int] -> Fe25519
  rest (Fe25519 r) (i:is)
    | Prelude.null is = nr
    | otherwise = rest nr is
      where
      (rst, rnd) = Prelude.splitAt (i + 1) r
      nr = Fe25519 $ Prelude.init rst ++ [255 .&. Prelude.last rst] ++
          (Prelude.head rnd + shiftR (rst !! i) 8) : Prelude.tail rnd

reduceAddSub :: Fe25519 -> Fe25519
reduceAddSub r = rep $ rep $ rep $ rep r
  where
  rep :: Fe25519 -> Fe25519
  rep (Fe25519 r) = rest (
    Fe25519 (

    times19 (shiftR (Prelude.last r) 7) + Prelude.head r
    :
    Prelude.init (Prelude.tail r) ++ [127 .&. Prelude.last r]
    )) [0..30]

  rest :: Fe25519 -> [Int] -> Fe25519
  rest (Fe25519 r) (i:is)
    | Prelude.null is = nr
    | otherwise = rest nr is
      where
      (rst, rnd) = Prelude.splitAt (i + 1) r
      nr = Fe25519 $ Prelude.init rst ++ [255 .&. Prelude.last rst] ++
          (Prelude.head rnd + shiftR (rst !! i) 8) : Prelude.tail rnd


  -- for(i=0;i<10;i++)
  -- {
  --   r[8*i+0]  =  s->v[3*i+0]       & 7;
  --   r[8*i+1]  = (s->v[3*i+0] >> 3) & 7;
  --   r[8*i+2]  = (s->v[3*i+0] >> 6) & 7;
  --   r[8*i+2] ^= (s->v[3*i+1] << 2) & 7;
  --   r[8*i+3]  = (s->v[3*i+1] >> 1) & 7;
  --   r[8*i+4]  = (s->v[3*i+1] >> 4) & 7;
  --   r[8*i+5]  = (s->v[3*i+1] >> 7) & 7;
  --   r[8*i+5] ^= (s->v[3*i+2] << 1) & 7;
  --   r[8*i+6]  = (s->v[3*i+2] >> 2) & 7;
  --   r[8*i+7]  = (s->v[3*i+2] >> 5) & 7;
  -- }
  -- r[8*i+0]  =  s->v[3*i+0]       & 7;
  -- r[8*i+1]  = (s->v[3*i+0] >> 3) & 7;
  -- r[8*i+2]  = (s->v[3*i+0] >> 6) & 7;
  -- r[8*i+2] ^= (s->v[3*i+1] << 2) & 7;
  -- r[8*i+3]  = (s->v[3*i+1] >> 1) & 7;
  -- r[8*i+4]  = (s->v[3*i+1] >> 4) & 7;
sc25519Window3 :: Sc25519 -> [Int]
sc25519Window3 s = signify (fromIntegral <$> fill s 0) 0 0
  where
    fill :: Sc25519 -> Int -> [Word32]
    fill (Sc25519 s) a
      | a == 10 = rest (Sc25519 s)
      | a < 10 =
            s!!(3*a+0)              .&. 7  :
          ( s!!(3*a+0) `shiftR` 3 ) .&. 7  :
          ((s!!(3*a+0) `shiftR` 6 ) .&. 7 ) `xor`
          ((s!!(3*a+1) `shiftL` 2 ) .&. 7 ):
          ( s!!(3*a+1) `shiftR` 1 ) .&. 7  :
          ( s!!(3*a+1) `shiftR` 4 ) .&. 7  :
          ((s!!(3*a+1) `shiftR` 7 ) .&. 7 ) `xor`
          ((s!!(3*a+2) `shiftL` 1 ) .&. 7 ):
          ( s!!(3*a+2) `shiftR` 2 ) .&. 7  :
          ( s!!(3*a+2) `shiftR` 5 ) .&. 7  :
          fill (Sc25519 s) (a+1)

    rest :: Sc25519 -> [Word32]
    rest (Sc25519 s) =
            s!!30              .&. 7  :
          ( s!!30 `shiftR` 3 ) .&. 7  :
          ((s!!30 `shiftR` 6 ) .&. 7 ) `xor`
          ((s!!31 `shiftL` 2 ) .&. 7 ):
          ( s!!31 `shiftR` 1 ) .&. 7  :
         [( s!!31 `shiftR` 4 ) .&. 7  ]

    signify :: [Int] -> Int -> Int -> [Int]
    signify r i carry
      | i == 84 = Prelude.init r ++ [Prelude.last r + carry]
      | i <  84 = signify newr (i+1) newcarry
      where
        (rst, rnd) = Prelude.splitAt (i+1) r
        ri = Prelude.last rst + carry
        ri1 = shiftR ri 3 + Prelude.head rnd
        rii = ri .&. 7
        newcarry = shiftR rii 2
        riii = rii - shiftL newcarry 3
        newr = Prelude.init rst ++ [riii] ++ [ri1] ++ Prelude.tail rnd

sc25519Mul :: Sc25519 -> Sc25519 -> Sc25519
sc25519Mul (Sc25519 x) (Sc25519 y) = barretReduce $ reduce 0 t
  where
    t = [sum [(x !! i) * (y !! j) |
      i <- [0..31],
      j <- [0..31],
      i+j == pos] |
      pos <- [0..63]]

    reduce i r
      | i < 63 = reduce (i+1) $ (Prelude.init rst ++ [Prelude.last rst .&. 0xff]) ++ (Prelude.head rnd + carry : Prelude.tail rnd)
      | i == 63 = r
      where
        carry = (r!!i) `shiftR` 8
        (rst, rnd) = Prelude.splitAt (i+1) r


barretReduce :: [Word32] -> Sc25519
barretReduce x = sc25519reduceAddSub $ sc25519reduceAddSub $ Sc25519 $ rep 0 0
  where
    addcarry i l = lst ++ ( Prelude.head lnd + (Prelude.last lst `shiftR` 8): Prelude.tail lnd )
      where
        (lst, lnd) = Prelude.splitAt i l

    q2 = addcarry 33 $ addcarry 32 $ [0 | x<-[0..30]] ++ [sum [ (mu!!i) * (x!!(j+31)) |
      i <- [0..32],
      j <- [0..32],
      i+j == pos] |
      pos <- [31..65]]
    r1 = Prelude.take 32 x ++ [0]
    r2 = rcarry 0 $ [sum [ (m!!i) * (q2!!(j+33))|
      i <- [0..33],
      j <- [0..32],
      i+j == pos] |
      pos <- [0..33]]

    rcarry i r
      | i == 32 = r
      | i < 32 = rcarry (i+1) $ Prelude.init rst ++
          [Prelude.last rst .&. 0xff] ++
          Prelude.head rnd + carry :
          Prelude.tail rnd
      where
        (rst, rnd) = Prelude.splitAt (i+1) r
        carry = Prelude.last rst `shiftR` 8

    rep i pb
      | i == 32 = []
      | i < 32 = (r1!!i) - pb1 + (b `shiftL` 8) : rep (i+1) b
      where
        pb1 = pb + (r2!!i)
        b = lt (r1!!i) pb1


sc25519Add :: Sc25519 -> Sc25519 -> Sc25519
sc25519Add (Sc25519 x) (Sc25519 y) = sc25519reduceAddSub . Sc25519 $ rcarry 0 [x!!i+y!!i | i<-[0..31]]
  where
    rcarry i r
      | i == 31 = r
      | i < 31 = rcarry (i+1) $ Prelude.init rst ++
          [Prelude.last rst .&. 0xff] ++
          Prelude.head rnd + carry :
          Prelude.tail rnd
      where
        (rst, rnd) = Prelude.splitAt (i+1) r
        carry = Prelude.last rst `shiftR` 8

sc25519reduceAddSub :: Sc25519 -> Sc25519
sc25519reduceAddSub (Sc25519 r) = Sc25519 [ (r!!i) `xor` ((k-1) .&. ((r!!i) `xor` (t!!i))) | i <- [0..31] ]
  where
    (t, k) = rep 0 0
    rep i pb
      | i == 32 = ([], pb)
      | i < 32 = ((r!!i) - pb1 + (b `shiftL` 8) : next, rb)
      where
        pb1 = pb + (m!!i)
        b = lt (r!!i) pb1
        (next, rb) = rep (i+1) b


lt :: Word32 -> Word32 -> Word32
lt a b = (a - b) `shiftR` 31


ge25519ScalarbaseMult s = rep 1 r
  where
    rep i rr
      | i == 85 = rr
      | otherwise = rep (i+1) $ ge25519Mixadd2 rr $ chooseT i (b !! i)


    b = sc25519Window3 s
    rxy = chooseT 0 $ Prelude.head b

    rx = Fe25519 $ x rxy
    ry = Fe25519 $ y rxy
    rz = Fe25519 setone
    rt = fe25519Mul rx ry

    r = Ge25519 {
      geX = rx,
      geY = ry,
      geZ = rz,
      geT = rt
    }


ge25519Mixadd2 :: Ge25519 -> Ge25519Aff -> Ge25519
ge25519Mixadd2 r q = Ge25519 {
  geX = fe25519Mul e f,
  geY = fe25519Mul h g,
  geZ = fe25519Mul g f,
  geT = fe25519Mul e h
  }
  where
    qt = fe25519Mul (Fe25519 $ x q) (Fe25519 $ y q)
    t1 = fe25519Sub (Fe25519 $ y q) (Fe25519 $ x q)
    t2 = fe25519Add (Fe25519 $ y q) (Fe25519 $ x q)
    a  = fe25519Mul (fe25519Sub (geY r) (geX r)) t1
    b  = fe25519Mul (fe25519Add (geY r) (geX r)) t2
    e  = fe25519Sub b a
    h  = fe25519Add b a
    c  = fe25519Mul (fe25519Mul (geT r) qt) ge25519_ec2d
    d  = fe25519Add (geZ r) (geZ r)
    f  = fe25519Sub d c
    g  = fe25519Add d c




fe25519Sub :: Fe25519 -> Fe25519 -> Fe25519
fe25519Sub (Fe25519 x) (Fe25519 y) = reduceAddSub $ Fe25519 [ t!!i - y!!i | i <- [0..31]]
  where
    t = 0x1da + Prelude.head x :
      [ 0x1fe + x!!i | i <- [1..30] ] ++
      [ 0xfe + Prelude.last x ]

fe25519Add :: Fe25519 -> Fe25519 -> Fe25519
fe25519Add (Fe25519 x) (Fe25519 y) = reduceAddSub $ Fe25519 [ x!!i + y!!i | i <- [0..31]]

fe25519Neg = fe25519Sub setzero

fe25519Sqaure :: Fe25519 -> Fe25519
fe25519Sqaure a = fe25519Mul a a

fe25519Invert x = up 5 z22500 z11
  where
    z2 = fe25519Sqaure x   -- 2 
    t1 = fe25519Sqaure z2  -- 4
    t0 = fe25519Sqaure t1  -- 8
    z9 = fe25519Mul t0 x   -- 9
    z11 = fe25519Mul z9 z2 -- 11
    z250 = fe25519Mul (fe25519Sqaure z11) z9 -- 2^5 - 2^0 = 31
    z2100 = up 5 z250 z250 -- 2^10 - 2^0
    z2200 = up 10 z2100 z2100 -- 2^20 - 2^0
    z2400 = up 20 z2200 z2200 -- 2^40 - 2^0
    z2500 = up 10 z2400 z2100 -- 2^50 - 2^0
    z21000 = up 50 z2500 z2500 -- 2^100 - 2^0
    z22000 = up 100 z21000 z21000 -- 2^200 - 2^0
    z22500 = up 50 z22000 z2500 -- 2^250 - 2^0
    up i a = fe25519Mul (sqr i a)
    sqr i a
      | i == 0 = a
      | i > 0 = sqr (i-1) $ fe25519Sqaure a



fe25519Freeze (Fe25519 r) =  (Prelude.head r - (m .&. 237)) : [ r!!x - (m .&. 255) | x <- [1..30] ] ++ [r!!31 - (m .&. 127)]
  where
    rep :: Int -> Word32
    rep i
      | 31 == i = equal (r!!i) 127 .&. rep (i-1)
      | 0 < i = equal (r!!i) 255 .&. rep (i-1)
      | 0 == i = ge (r!!i) 237
    m = -rep 31

fe25519Pack :: Fe25519 -> [Word8]
fe25519Pack x = fromIntegral <$> fe25519Freeze x

fe25519GetParity x = Prelude.head (fe25519Freeze x)  .&. 1

ge a b = x `xor` 1
  where
  x :: Word32
  x = fromIntegral (a - b) `shiftR` 31

ge25519Pack :: Ge25519 -> [Word8]
ge25519Pack p =  Prelude.init r ++ [r31]
  where
    zi = fe25519Invert (geZ p)
    tx = fe25519Mul (geX p) zi
    ty = fe25519Mul (geY p) zi
    r = fe25519Pack ty
    r31 = xor (r!!31) $ fromIntegral (fe25519GetParity tx) `shiftL` 7





----------------------------------------------------------------
-------- These should be O(1) to prevent timing attacks --------
----------------------------------------------------------------
-- It's not important that this actually is for this project

-- In other implementations where Ints have fixed size there is bit shifting.
-- == is not O(1)
equal b c = if b == c then 1 else 0


geequal b c = r
  where
    r :: Word32
    r = (fromIntegral (ub `xor` uc) - 1) `shiftR` 31
    ub :: Word8
    ub = fromIntegral b
    uc :: Word8
    uc = fromIntegral c

cmov :: Fe25519 -> Fe25519 -> Integer -> Fe25519
cmov (Fe25519 r) (Fe25519 x) b = Fe25519 [ri `xor` (m .&. (xi `xor` ri)) | (xi, ri) <- Prelude.zip x r]
  where
    m :: Word32
    m = fromIntegral (-b)

neg :: [Integer] -> [Integer]
neg f = (* (-1)) <$> f

negative b
  | b < 0 = 1
  | b >= 0 = 0

times38 a = shiftL a 5 + shiftL a 2 + shiftL a 1
times19 a = shiftL a 4 + shiftL a 1 + a
----------------------------------------------------------------
-------- These should be O(1) to prevent timing attacks --------
----------------------------------------------------------------



main = do
  hSetBuffering stdout NoBuffering
  Prelude.putStr "Private Key (32): "
  privateKey <- Prelude.getLine
  let (Just prv) = TH.decodeHex $ Data.Text.pack $ Prelude.take 64 privateKey
  pub <- Data.Text.unpack . TH.encodeHex . BS.pack . generatePublicKey <$> SHA512.hashByteString prv
  Prelude.putStrLn $ "Public Key: " ++ pub

  Prelude.putStr "Message: "
  message <- Prelude.getLine 
  let m :: ByteString; m = DS.fromString message
  print m 

  let sig = Data.Text.unpack . TH.encodeHex . BS.pack <$> sign (BS.unpack m) prv
  s <- sig
  Prelude.putStr $ "Signature: " ++ s


sig = sign [0xab] pp
message = [0x54,0x68,0x69,0x73,0x20,0x69,0x73,0x20,0x61,0x20,0x74,0x6f,0x79]
rawkey = "A64D31C6F3922DED32CA240618B69A87AC422815ECD023009584DF84B573F12B"
(Just pp) = TH.decodeHex $ Data.Text.pack rawkey





