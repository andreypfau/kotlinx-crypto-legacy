package io.github.andreypfau.kotlinx.crypto.aes

import io.github.andreypfau.kotlinx.crypto.cipher.BlockCipher
import javax.crypto.Cipher
import javax.crypto.spec.SecretKeySpec

public actual class AesCipher actual constructor(key: ByteArray) : BlockCipher {
    override val algorithmName: String get() = AesCipherCommon.ALGORITHM_NAME
    override val blockSize: Int get() = AesCipherCommon.BLOCK_SIZE
    private val cipherJvm = Cipher.getInstance("AES").apply {
        val secretKey = SecretKeySpec(key, "AES")
        init(Cipher.ENCRYPT_MODE, secretKey)
    }

    override fun encryptIntoByteArray(
        source: ByteArray,
        destination: ByteArray,
        destinationOffset: Int,
        startIndex: Int,
        endIndex: Int
    ): Int {
        return cipherJvm.update(source, startIndex, endIndex - startIndex, destination, destinationOffset)
    }
}
