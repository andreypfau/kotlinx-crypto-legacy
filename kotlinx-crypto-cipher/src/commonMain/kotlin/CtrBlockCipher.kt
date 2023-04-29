package io.github.andreypfau.kotlinx.crypto.cipher

import kotlin.experimental.xor

private const val STREAM_BUF_SIZE = 512

public class CtrBlockCipher(
    public val cipher: BlockCipher,
    iv: ByteArray
) : StreamCipher {
    private val buffer: ByteArray
    private val ctr: ByteArray
    private var counter = cipher.blockSize

    init {
        require(iv.size == cipher.blockSize) {
            "IV length must equal block size, expected: ${cipher.blockSize}, actual: ${iv.size}"
        }
        ctr = iv.copyOf()
        val bufSize = if (STREAM_BUF_SIZE < cipher.blockSize) {
            cipher.blockSize
        } else {
            STREAM_BUF_SIZE
        }
        buffer = ByteArray(bufSize)
    }

    override fun encryptIntoByteArray(
        source: ByteArray,
        destination: ByteArray,
        destinationOffset: Int,
        startIndex: Int,
        endIndex: Int
    ): Int {
        val sourceLength = endIndex - startIndex

        for (i in 0 until sourceLength) {
            if (counter == cipher.blockSize) {
                ctr.copyInto(buffer)
                cipher.encryptIntoByteArray(buffer, buffer)

                for (j in cipher.blockSize - 1 downTo 0) {
                    if (ctr[j] == 0xFF.toByte()) {
                        ctr[j] = 0
                    } else {
                        ctr[j]++
                        break
                    }
                }
                counter = 0
            }
            destination[destinationOffset + i] = source[startIndex + i] xor buffer[counter]
            counter++
        }

        return sourceLength
    }
}
