package io.github.andreypfau.kotlinx.crypto.sha256

import io.github.andreypfau.kotlinx.crypto.digest.Digest
import java.security.MessageDigest

public actual class Sha256Digest : Digest {
    private val jvmDigest = MessageDigest.getInstance("SHA-256")
    override val algorithmName: String get() = Sha256DigestCommon.ALGORITHM_NAME
    override val digestSize: Int get() = Sha256DigestCommon.SIZE_BYTES

    override fun update(input: Byte) {
        jvmDigest.update(input)
    }

    override fun update(input: ByteArray, offset: Int, length: Int) {
        if (length == 0) return
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
