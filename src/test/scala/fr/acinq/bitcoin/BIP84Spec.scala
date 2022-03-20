package fr.acinq.bitcoin

import fr.acinq.bitcoin.Crypto.PublicKey
import fr.acinq.bitcoin.DeterministicWallet.KeyPath
import org.scalatest.FunSuite
import scodec.bits._

/**
  * BIP 84 (Derivation scheme for P2WPKH based accounts) reference tests
  * see https://github.com/bitcoin/bips/blob/master/bip-0084.mediawiki
  */
class BIP84Spec extends FunSuite {
  test("BIP49 reference tests") {
    val seed = MnemonicCode.toSeed("abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about", "")
    val master = DeterministicWallet.generate(seed)
    assert(DeterministicWallet.encode(master, DeterministicWallet.zprv) == "zprvAWgYBBk7JR8Gjrh4UJQ2uJdG1r3WNRRfURiABBE3RvMXYSrRJL62XuezvGdPvG6GFBZduosCc1YP5wixPox7zhZLfiUm8aunE96BBa4Kei5")
    assert(DeterministicWallet.encode(DeterministicWallet.publicKey(master), DeterministicWallet.zpub) == "zpub6jftahH18ngZxLmXaKw3GSZzZsszmt9WqedkyZdezFtWRFBZqsQH5hyUmb4pCEeZGmVfQuP5bedXTB8is6fTv19U1GQRyQUKQGUTzyHACMF")

    val accountKey = DeterministicWallet.derivePrivateKey(master, KeyPath("m/84'/22'/0'"))
    assert(DeterministicWallet.encode(accountKey, DeterministicWallet.zprv) == "zprvAcZ5F4WJkcPfLQbTgjhcNt4sxGSXFxHWyLZsxd8fENCMFKRhc32Xjdwo4WMje5zhNzy2WeqoHYWFhNittqCHD96Bj1mM7eFVdf5oNhahGtx")
    assert(DeterministicWallet.encode(DeterministicWallet.publicKey(accountKey), DeterministicWallet.zpub) == "zpub6qYRea3CaywxYtfvnmEck21cWJH1fR1NLZVUm1YGnhjL87kr9aLnHSGGumibCJWR9SswtGCuK15Z57WC18oJzkAhZXCTcWTcdHJMfbydrok")

    val key = DeterministicWallet.derivePrivateKey(accountKey, 0L :: 0L :: Nil)
    assert(key.secretkeybytes == DeterministicWallet.derivePrivateKey(master, KeyPath("m/84'/22'/0'/0/0")).secretkeybytes)
    assert(key.privateKey.toBase58(Base58.Prefix.SecretKey) == "TAWKTY1ch7Zay7DggupUoHCbkJY4HxXp5oGU6DXVofVq68f5i8t4")
    assert(key.publicKey == PublicKey(hex"02501db0fe8b6003439eb434a818f4fe24865b9eae20461070f50601dc9bc68426"))
    assert(computeBIP84Address(key.publicKey, Block.LivenetGenesisBlock.hash) == "mona1qpgmk2vdx5ve6xm93rplw9d6uszpe4am5my7x72")

    val key1 = DeterministicWallet.derivePrivateKey(accountKey, 0L :: 1L :: Nil)
    assert(key1.secretkeybytes == DeterministicWallet.derivePrivateKey(master, KeyPath("m/84'/22'/0'/0/1")).secretkeybytes)
    assert(key1.privateKey.toBase58(Base58.Prefix.SecretKey) == "T49phmvFNh5bzDpvzE1iUgdtuq7JiruVo2R34nGcYSU7CbJYoSoB")
    assert(key1.publicKey == PublicKey(hex"0292505225edc87cc6017ee4ca6d6dccc891b16b23fec9a7f161b87e7c3fbf1475"))
    assert(computeBIP84Address(key1.publicKey, Block.LivenetGenesisBlock.hash) == "mona1qrxn93s4m5wlg029z4mzwlwyc7r7efml9ku0ama")

    val key2 = DeterministicWallet.derivePrivateKey(accountKey, 1L :: 0L :: Nil)
    assert(key2.secretkeybytes == DeterministicWallet.derivePrivateKey(master, KeyPath("m/84'/22'/0'/1/0")).secretkeybytes)
    assert(key2.privateKey.toBase58(Base58.Prefix.SecretKey) == "T46eKCC5ngZk6zQL2rpewxBMRgN8HEJfTrPeaNW1DuwJVfkzCZf8")
    assert(key2.publicKey == PublicKey(hex"02389c16bfd721115c6f1e9fbb66f88e437da724cef7015f027a5732389dcd4c7e"))
    assert(computeBIP84Address(key2.publicKey, Block.LivenetGenesisBlock.hash) == "mona1q7t5p3u22skphsflmxnta7tjw8kspf7s35q793e")
  }
}
