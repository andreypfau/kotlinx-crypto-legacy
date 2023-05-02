package io.github.andreypfau.kotlinx.crypto.aes

import io.github.andreypfau.kotlinx.crypto.cipher.BlockCipher

public expect class AesCipher public constructor(key: ByteArray) : BlockCipher

public class AesCipherCommon(
    key: ByteArray,
) : BlockCipher {

    private val encryptKey: IntArray
    private val decryptKey: IntArray

    init {
        require(key.size == 16 || key.size == 24 || key.size == 32) {
            "invalid key size, expected: 16/24/32, actual: ${key.size}"
        }
        val n = key.size + 28
        encryptKey = IntArray(n)
        decryptKey = IntArray(n)
        aesExpandKey(key, encryptKey, decryptKey)
    }

    override val algorithmName: String get() = ALGORITHM_NAME

    override val blockSize: Int get() = BLOCK_SIZE

    override fun encryptIntoByteArray(
        source: ByteArray,
        destination: ByteArray,
        destinationOffset: Int,
        startIndex: Int,
        endIndex: Int
    ): Int {
        check(endIndex - startIndex >= BLOCK_SIZE) {
            "source not full block"
        }
        check(destination.size - destinationOffset >= BLOCK_SIZE) {
            "destination not full block"
        }
        aesEncryptBlock(encryptKey, source, startIndex, destination, destinationOffset)
        return blockSize
    }

    public companion object {
        public const val ALGORITHM_NAME: String = "AES"
        public const val BLOCK_SIZE: Int = 16
    }
}
