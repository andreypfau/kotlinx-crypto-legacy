package io.github.andreypfau.kotlinx.crypto.aes

import io.github.andreypfau.kotlinx.crypto.cipher.BlockCipher

public class AesCipher(
    key: ByteArray,
    decrypt: Boolean
) : BlockCipher {
    public constructor(key: ByteArray) : this(key, decrypt = true)

    private val encryptKey: IntArray
    private val decryptKey: IntArray

    init {
        require(key.size == 16 || key.size == 24 || key.size == 32) {
            "invalid key size, expected: 16/24/32, actual: ${key.size}"
        }
        val n = key.size + 28
        encryptKey = IntArray(n)
        decryptKey = IntArray(if (decrypt) n else 0)
        aesExpandKey(key, encryptKey, decryptKey)
    }

    override val algorithmName: String get() = "AES"

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
        public const val BLOCK_SIZE: Int = 16
    }
}
