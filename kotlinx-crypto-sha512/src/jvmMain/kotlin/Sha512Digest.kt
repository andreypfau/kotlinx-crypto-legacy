package io.github.andreypfau.kotlinx.crypto.sha512

import io.github.andreypfau.kotlinx.crypto.digest.Digest
import java.security.MessageDigest

public actual class Sha512Digest : Digest {
    private val jvmDigest = MessageDigest.getInstance("SHA-512")
    override val algorithmName: String get() = Sha512DigestCommon.ALGORITHM_NAME
    override val digestSize: Int get() = Sha512DigestCommon.SIZE_BYTES

    override fun update(input: Byte) {
        jvmDigest.update(input)
    }

    override fun update(input: ByteArray, offset: Int, length: Int) {
        jvmDigest.update(input, offset, length)
    }

    override fun build(output: ByteArray, offset: Int): ByteArray {
        jvmDigest.digest(output, offset, digestSize)
        return output
    }

    override fun reset() {
        jvmDigest.reset()
    }
}
