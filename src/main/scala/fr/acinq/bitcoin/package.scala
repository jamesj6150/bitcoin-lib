package fr.acinq

import java.io._
import java.math.BigInteger

/**
 * see https://en.bitcoin.it/wiki/Protocol_specification
 */
package object bitcoin {
  val Coin = 100000000L
  val Cent = 1000000L
  val MaxMoney = 21000000 * Coin
  val MaxScriptElementSize = 520
  val MaxBlockSize = 1000000
  val LockTimeThreshold = 500000000L
  val SequenceThreshold = 1L << 31

  /**
   * signature hash flags
   */
  val SIGHASH_ALL = 1
  val SIGHASH_NONE = 2
  val SIGHASH_SINGLE = 3
  val SIGHASH_ANYONECANPAY = 0x80

  object Hash {
    val Zeroes: BinaryData = "0000000000000000000000000000000000000000000000000000000000000000"
    val One: BinaryData = "0100000000000000000000000000000000000000000000000000000000000000"
  }

  def toHexString(blob: Seq[Byte]) = blob.map("%02x".format(_)).mkString

  def fromHexString(hex: String): Array[Byte] = hex.stripPrefix("0x").sliding(2, 2).toArray.map(Integer.parseInt(_, 16).toByte)

  implicit def string2binaryData(input: String) : BinaryData = BinaryData(fromHexString(input))

  implicit def seq2binaryData(input: Seq[Byte]) : BinaryData = BinaryData(input)

  implicit def array2binaryData(input: Array[Byte]) : BinaryData = BinaryData(input)

  implicit def binaryData2array(input: BinaryData) : Array[Byte] = input.data.toArray

  implicit def binaryData2Seq(input: BinaryData) : Seq[Byte] = input.data

  /**
   *
   * @param input compact size encoded integer as used to encode proof-of-work difficulty target
   * @return a (result, isNegative, overflow) tuple were result is the decoded integer
   */
  def decodeCompact(input: Long): (BigInteger, Boolean, Boolean) = {
    val nSize = (input >> 24).toInt
    val (nWord, result) = if (nSize <= 3) {
      val nWord1 = (input & 0x007fffffL) >> 8 * (3 - nSize)
      (nWord1, BigInteger.valueOf(nWord1))
    } else {
      val nWord1 = (input & 0x007fffffL)
      (nWord1, BigInteger.valueOf(nWord1).shiftLeft(8 * (nSize - 3)))
    }
    val isNegative = nWord != 0 && (input & 0x00800000) != 0
    val overflow = nWord != 0 && ((nSize > 34) || (nWord > 0xff && nSize > 33) || (nWord > 0xffff && nSize > 32))
    (result, isNegative, overflow)
  }

  def isAnyoneCanPay(sighashType: Int): Boolean = (sighashType & SIGHASH_ANYONECANPAY) != 0

  def isHashSingle(sighashType: Int): Boolean = (sighashType & 0x1f) == SIGHASH_SINGLE

  def isHashNone(sighashType: Int): Boolean = (sighashType & 0x1f) == SIGHASH_NONE
}
