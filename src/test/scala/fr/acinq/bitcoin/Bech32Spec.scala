package fr.acinq.bitcoin

import org.scalatest.FunSuite
import scodec.bits._

/**
  * Created by fabrice on 19/04/17.
  */
class Bech32Spec extends FunSuite {
  test("valid checksums") {
    val inputs = Seq(
      "A12UEL5L",
      "a12uel5l",
      "an83characterlonghumanreadablepartthatcontainsthenumber1andtheexcludedcharactersbio1tt5tgs",
      "abcdef1qpzry9x8gf2tvdw0s3jn54khce6mua7lmqqqxw",
      "11qqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqc8247j",
      "split1checkupstagehandshakeupstreamerranterredcaperred2y9e3w",
      "?1ezyfcl"
    )
    val outputs = inputs.map(Bech32.decode)
    assert(outputs.length == inputs.length)
  }

  test("invalid checksums") {
    val inputs = Seq(
      " 1nwldj5",
      "\u007f1axkwrx",
      "an84characterslonghumanreadablepartthatcontainsthenumber1andtheexcludedcharactersbio1569pvx",
      "pzry9x0s0muk",
      "1pzry9x0s0muk",
      "x1b4n0q5v",
      "li1dgmt3",
      "de1lg7wt\u00ff"
    )

    inputs.map(address => {
      intercept[Exception] {
        Bech32.decodeWitnessAddress(address)
      }
    })
  }

  test("decode addresses") {
    val inputs = Seq(
      "MONA1Q4KPN6PSTHGD5UR894AUHJJ2G02WLGMP8KE08NE" -> "0014ad833d060bba1b4e0ce5af797949487a9df46c27",
      "mona1qp8f842ywwr9h5rdxyzggex7q3trvvvaarfssxccju52rj6htfzfsqr79j2" -> "002009d27aa88e70cb7a0da620908c9bc08ac6c633bd1a61036312e514396aeb4893",
      "mona1pw508d6qejxtdg4y5r3zarvary0c5xw7kw508d6qejxtdg4y5r3zarvary0c5xw7k9xvmwr" -> "5128751e76e8199196d454941c45d1b3a323f1433bd6751e76e8199196d454941c45d1b3a323f1433bd6",
      "mona1sw50qpvnxy8" -> "6002751e",
      "mona1zw508d6qejxtdg4y5r3zarvaryvhm3vz7" -> "5210751e76e8199196d454941c45d1b3a323",
      "tmona1qqqqqp399et2xygdj5xreqhjjvcmzhxw4aywxecjdzew6hylgvseszfvrwg" -> "0020000000c4a5cad46221b2a187905e5266362b99d5e91c6ce24d165dab93e86433"
    )
    inputs.map {
      case (address, bin) =>
        val (_, _, bin1) = Bech32.decodeWitnessAddress(address)
        assert(bin1.toHex == bin.substring(4))
    }
  }

  test("create addresses") {
    assert(Bech32.encodeWitnessAddress("mona", 0, hex"751e76e8199196d454941c45d1b3a323f1433bd6") == "MONA1QW508D6QEJXTDG4Y5R3ZARVARY0C5XW7KG5LNX5".toLowerCase)
    assert(Bech32.encodeWitnessAddress("tmona", 0, hex"1863143c14c5166804bd19203356da136c985678cd4d27a1b8c6329604903262") == "tmona1qrp33g0q5c5txsp9arysrx4k6zdkfs4nce4xj0gdcccefvpysxf3qwlyd0j")
    assert(Bech32.encodeWitnessAddress("tmona", 0, hex"000000c4a5cad46221b2a187905e5266362b99d5e91c6ce24d165dab93e86433") == "tmona1qqqqqp399et2xygdj5xreqhjjvcmzhxw4aywxecjdzew6hylgvseszfvrwg")
  }

  test("reject invalid addresses") {
    val addresses = Seq(
      "tnamo1qw508d6qejxtdg4y5r3zarvary0c5xw7kumwy3n",
      "mona1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t5c2see9",
      "MONA13W508D6QEJXTDG4Y5R3ZARVARY0C5XW7KHXEVYT",
      "mona1rw5gv2qqg",
      "mona10w508d6qejxtdg4y5r3zarvary0c5xw7kw508d6qejxtdg4y5r3zarvary0c5xw7kw56ms2yd",
      "mona10w508d6qejxtdg4y5r3zarvary0c5xw7kw508d6qejxtdg4y5r3zarvary0c5xw7kw56ms2yd234567789035",
      "MONA1QR508D6QEJXTDG4Y5R3ZARVARYV6X0N6D",
      "tmona1qrp33g0q5c5txsp9arysrx4k6zdkfs4nce4xj0gdcccefvpysxf3qwLyd0j",
      "mona1zw508d6qejxtdg4y5r3zarvaryvq0fn2th",
      "tmona1qrp33g0q5c5txsp9arysrx4k6zdkfs4nce4xj0gdcccefvpysxf3pnfscjq",
      "mona1c0fp8z"
    )
    addresses.map(address => {
      intercept[Exception] {
        Bech32.decodeWitnessAddress(address)
      }
    })
  }
}
