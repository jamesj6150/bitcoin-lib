package fr.acinq.bitcoin

import java.math.BigInteger
import java.net.InetAddress

import com.google.common.io.ByteStreams
import org.scalatest.FlatSpec
import scodec.bits._

class ProtocolSpec extends FlatSpec {
  "Protocol" should "parse blochain blocks" in {
    val stream = classOf[ProtocolSpec].getResourceAsStream("/block1.dat")
    val block = Block.read(stream)
    assert(Block.checkProofOfWork(block))
    // check that we can deserialize and re-serialize scripts
    block.tx.map(tx => {
      tx.txIn.map(txin => {
        if (!OutPoint.isCoinbase(txin.outPoint)) {
          val script = Script.parse(txin.signatureScript)
          assert(txin.signatureScript == Script.write(script))
        }
      })
      tx.txOut.map(txout => {
        val script = Script.parse(txout.publicKeyScript)
        assert(txout.publicKeyScript == Script.write(script))
      })
    })
  }
  it should "serialize/deserialize blocks" in {
    val stream = classOf[ProtocolSpec].getResourceAsStream("/block1.dat")
    val bytes = ByteStreams.toByteArray(stream)
    val block = Block.read(bytes)
    val check = Block.write(block)
    assert(check == ByteVector.view(bytes))
  }
  it should "decode transactions" in {
    // data copied from https://people.xiph.org/~greg/signdemo.txt
    val tx = Transaction.read("01000000010c432f4fb3e871a8bda638350b3d5c698cf431db8d6031b53e3fb5159e59d4a90000000000ffffffff0100f2052a010000001976a9143744841e13b90b4aca16fe793a7f88da3a23cc7188ac00000000")
    val script = Script.parse(tx.txOut(0).publicKeyScript)
    val publicKeyHash = Script.publicKeyHash(script)
    assert(Base58Check.encode(Base58.Prefix.PubkeyAddressTestnet, publicKeyHash) === "mkZBYBiq6DNoQEKakpMJegyDbw2YiNQnHT")
  }
  it should "generate genesis block" in {
    assert(Block.write(Block.LivenetGenesisBlock) === hex"0x010000000000000000000000000000000000000000000000000000000000000000000000A64BAC07FE31877F31D03252953B3C32398933AF7A724119BC4D6FA4A805E435F083C252F0FF0F1E66D612000101000000010000000000000000000000000000000000000000000000000000000000000000FFFFFFFF5F04FFFF001D01044C564465632E20333174682032303133204A6170616E2C205468652077696E6E696E67206E756D62657273206F6620746865203230313320596561722D456E64204A756D626F204C6F74746572793A32332D313330393136FFFFFFFF0100F2052A010000004341040184710FA689AD5023690C80F3A49C8F13F8D45B8C857FBCBC8BC4A8E4D3EB4B10F4D4604FA08DCE601AAF0F470216FE1B51850B4ACF21B179C45070AC7B03A9AC00000000")
    assert(Block.LivenetGenesisBlock.blockId === ByteVector32(hex"ff9f1c0116d19de7c9963845e129f9ed1bfc0b376eb54fd7afa42e0d418c8bb6"))
    assert(Block.TestnetGenesisBlock.blockId === ByteVector32(hex"a2b106ceba3be0c6d097b2a6a6aacf9d638ba8258ae478158f449c321061e0b2"))
    assert(Block.RegtestGenesisBlock.blockId === ByteVector32(hex"7543a69d7c2fcdb29a5ebec2fc064c074a35253b6f3072c8a749473aa590a29c"))
    assert(Block.SegnetGenesisBlock.blockId === ByteVector32(hex"253ac280610723c8af3d1dfef699a7549ef01371d40b552cc3d34d090c6e5c81"))
  }
  it should "decode proof-of-work difficulty" in {
    assert(decodeCompact(0) === (BigInteger.ZERO, false, false))
    assert(decodeCompact(0x00123456) === (BigInteger.ZERO, false, false))
    assert(decodeCompact(0x01003456) === (BigInteger.ZERO, false, false))
    assert(decodeCompact(0x02000056) === (BigInteger.ZERO, false, false))
    assert(decodeCompact(0x03000000) === (BigInteger.ZERO, false, false))
    assert(decodeCompact(0x04000000) === (BigInteger.ZERO, false, false))
    assert(decodeCompact(0x00923456) === (BigInteger.ZERO, false, false))
    assert(decodeCompact(0x01803456) === (BigInteger.ZERO, false, false))
    assert(decodeCompact(0x02800056) === (BigInteger.ZERO, false, false))
    assert(decodeCompact(0x03800000) === (BigInteger.ZERO, false, false))
    assert(decodeCompact(0x04800000) === (BigInteger.ZERO, false, false))
    assert(decodeCompact(0x01123456) === (BigInteger.valueOf(0x12), false, false))
    assert(decodeCompact(0x01fedcba) === (BigInteger.valueOf(0x7e), true, false))
    assert(decodeCompact(0x02123456) === (BigInteger.valueOf(0x1234), false, false))
    assert(decodeCompact(0x03123456) === (BigInteger.valueOf(0x123456), false, false))
    assert(decodeCompact(0x04123456) === (BigInteger.valueOf(0x12345600), false, false))
    assert(decodeCompact(0x04923456) === (BigInteger.valueOf(0x12345600), true, false))
    assert(decodeCompact(0x05009234) === (new BigInteger(1, hex"92340000".toArray), false, false))
    assert(decodeCompact(0x20123456) === (new BigInteger(1, hex"1234560000000000000000000000000000000000000000000000000000000000".toArray), false, false))
    val (_, false, true) = decodeCompact(0xff123456L)
  }
  it should "read and write version messages" in {
    val version = Version(
      0x00011172L,
      services = 1L,
      timestamp = 0x53c420c4L,
      addr_recv = NetworkAddress(1L, InetAddress.getByAddress(Array(85.toByte, 235.toByte, 17.toByte, 3.toByte)), 18333L),
      addr_from = NetworkAddress(1L, InetAddress.getByAddress(Array(109.toByte, 24.toByte, 186.toByte, 185.toByte)), 18333L),
      nonce = 0x4317be39ae6ea291L,
      user_agent = "/Satoshi:0.9.99/",
      start_height = 0x00041a23L,
      relay = true)

    assert(Version.write(version) === hex"721101000100000000000000c420c45300000000010000000000000000000000000000000000ffff55eb1103479d010000000000000000000000000000000000ffff6d18bab9479d91a26eae39be1743102f5361746f7368693a302e392e39392f231a040001")

    val message = Message(magic = 0x0709110bL, command = "version", payload = Version.write(version))
    assert(Message.write(message) === hex"0b11090776657273696f6e0000000000660000008c48bb56721101000100000000000000c420c45300000000010000000000000000000000000000000000ffff55eb1103479d010000000000000000000000000000000000ffff6d18bab9479d91a26eae39be1743102f5361746f7368693a302e392e39392f231a040001")

    val message1 = Message.read(Message.write(message).toArray)
    assert(message1.command === "version")
    val version1 = Version.read(message1.payload.toArray)
    assert(version1 === version)
  }
  it should "read and write verack messages" in {
    val message = Message.read("0b11090776657261636b000000000000000000005df6e0e2")
    assert(message.command === "verack")
    assert(message.payload.isEmpty)

    val message1 = Message(magic = 0x0709110bL, command = "verack", payload = ByteVector.empty)
    assert(Message.write(message1) === hex"0b11090776657261636b000000000000000000005df6e0e2")
  }
  it should "read and write addr messages" in {
    // example take from https://en.bitcoin.it/wiki/Protocol_specification#addr
    val message = Message.read("f9beb4d96164647200000000000000001f000000ed52399b01e215104d010000000000000000000000000000000000ffff0a000001208d")
    assert(message.command === "addr")
    val addr = Addr.read(message.payload.toArray)
    assert(addr.addresses.length === 1)
    assert(addr.addresses(0).address.getAddress === Array(10: Byte, 0: Byte, 0: Byte, 1: Byte))
    assert(addr.addresses(0).port === 8333)

    val addr1 = Addr(List(NetworkAddressWithTimestamp(time = 1292899810L, services = 1L, address = InetAddress.getByAddress(Array(10: Byte, 0: Byte, 0: Byte, 1: Byte)), port = 8333)))
    val message1 = Message(magic = 0xd9b4bef9, command = "addr", payload = Addr.write(addr1))
    assert(Message.write(message1) === hex"f9beb4d96164647200000000000000001f000000ed52399b01e215104d010000000000000000000000000000000000ffff0a000001208d")
  }
  it should "read and write addr messages 2" in {
    val stream = classOf[ProtocolSpec].getResourceAsStream("/addr.dat")
    val message = Message.read(stream)
    assert(message.command === "addr")
    val addr = Addr.read(message.payload.toArray)
    assert(addr.addresses.length === 1000)
  }
  it should "read and write inventory messages" in {
    val inventory = Inventory.read("01010000004d43a12ddedc1638542a4c5a5dff3fc5daa9bd543ecccbe8c7eed8648044668f")
    assert(inventory.inventory.length === 1)
    assert(inventory.inventory(0).`type` === InventoryVector.MSG_TX)
  }
  it should "read and write inventory messages 2" in {
    val stream = classOf[ProtocolSpec].getResourceAsStream("/inv.dat")
    val message = Message.read(stream)
    assert(message.command === "inv")
    val inv = Inventory.read(message.payload.toArray)
    assert(inv.inventory.size === 500)
    assert(message.payload == Inventory.write(inv))
  }
  it should "read and write getblocks messages" in {
    val message = Message.read("f9beb4d9676574626c6f636b7300000045000000f5fcbcad72110100016fe28c0ab6f1b372c1a6a246ae63f74f931e8365e15a089c68d61900000000000000000000000000000000000000000000000000000000000000000000000000")
    assert(message.command == "getblocks")
    val getblocks = Getblocks.read(message.payload.toArray)
    assert(getblocks.version === 70002)
    assert(getblocks.locatorHashes.head === hex"6fe28c0ab6f1b372c1a6a246ae63f74f931e8365e15a089c68d6190000000000")
    assert(Getblocks.write(getblocks) === message.payload)
  }
  it should "read and write getheaders message" in {
    val getheaders = Getheaders.read("71110100019ca290a53a4749a7c872306f3b25354a074c06fcc2be5e9ab2cd2f7c9da643750000000000000000000000000000000000000000000000000000000000000000")
    assert(getheaders.locatorHashes(0) === Block.RegtestGenesisBlock.hash)
    assert(Getheaders.write(getheaders) === hex"71110100019ca290a53a4749a7c872306f3b25354a074c06fcc2be5e9ab2cd2f7c9da643750000000000000000000000000000000000000000000000000000000000000000")
  }
  it should "read and write getdata messages" in {
    val stream = classOf[ProtocolSpec].getResourceAsStream("/getdata.dat")
    val message = Message.read(stream)
    assert(message.command === "getdata")
    val getdata = Getdata.read(message.payload.toArray)
    assert(getdata.inventory.size === 128)
    assert(getdata.inventory(0).hash === hex"4860eb18bf1b1620e37e9490fc8a427514416fd75159ab86688e9a8300000000")
    val check = Getdata.write(getdata)
    assert(check == message.payload)
  }
  it should "read and write block messages" in {
    val message = Message.read("f9beb4d9626c6f636b00000000000000d7000000934d270a010000006fe28c0ab6f1b372c1a6a246ae63f74f931e8365e15a089c68d6190000000000982051fd1e4ba744bbbe680e1fee14677ba1a3c3540bf7b1cdb606e857233e0e61bc6649ffff001d01e362990101000000010000000000000000000000000000000000000000000000000000000000000000ffffffff0704ffff001d0104ffffffff0100f2052a0100000043410496b538e853519c726a2c91e61ec11600ae1390813a627c66fb8be7947be63c52da7589379515d4e0a604f8141781e62294721166bf621e73a82cbf2342c858eeac00000000")
    assert(message.command === "block")
    val block = Block.read(message.payload.toArray)
    //assert(block.header.hashPreviousBlock == Block.LivenetGenesisBlock.hash) // TODO monacoin is OK?
    assert(OutPoint.isCoinbase(block.tx(0).txIn(0).outPoint))
    assert(Block.checkProofOfWork(block))
  }
  it should "check proof of work" in {
    val headers = Seq(
      "01000000d46774a07109e9863938acd67fd7adf0b265293a38283f29a7e2551600000000256713d0e1b31f2518e7f93b41b9392da12dcd15fd9b871d2f694bfa6e4aaa308d06c34fc0ff3f1c7520e9f3",
      "0200000035ab154183570282ce9afc0b494c9fc6a3cfea05aa8c1add2ecc56490000000038ba3d78e4500a5a7570dbe61960398add4410d278b21cd9708e6d9743f374d544fc055227f1001c29c1ea3b",
      "000000201af2487466dc0437a1fc545740abd82c9d51b5a4bab9e5fea5082200000000000b209c935968affb31bd1288e66203a2b635b902a2352f7867b85201f6baaf09044d0758c0cc521bd1cf559f",
      "00000020620187836ab16deef958960bc1f8321fe2c32971a447ba7888bc050000000000c91a344b1a95579235f66776652529c60fd50099af021977f073388abb44862e8fbdda58c0b3271ca4e63787"
    ).map(BlockHeader.read)

    headers.foreach(header => assert(BlockHeader.checkProofOfWork(header)))
  }
  it should "read and write reject messages" in {
    val message = Message.read("0b11090772656a6563740000000000001f00000051e3a01d076765746461746101156572726f722070617273696e67206d657373616765")
    assert(message.command === "reject")
    val reject = Reject.read(message.payload.toArray)
    assert(reject.message === "getdata")
    assert(Reject.write(reject) == message.payload)
  }
}
