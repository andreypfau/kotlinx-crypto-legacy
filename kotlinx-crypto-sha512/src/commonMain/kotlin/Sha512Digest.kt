package io.github.andreypfau.kotlinx.crypto.sha512

import io.github.andreypfau.kotlinx.crypto.digest.Digest
import io.github.andreypfau.kotlinx.crypto.digest.LongDigest
import io.github.andreypfau.kotlinx.encoding.binary.Binary.storeLongAt

public expect class Sha512Digest public constructor() : Digest

/**
 * FIPS 180-2 implementation of SHA-512.
 *
 * ```
 *         block  word  digest
 * SHA-1   512    32    160
 * SHA-256 512    32    256
 * SHA-384 1024   64    384
 * SHA-512 1024   64    512
 * ```
 */
public class Sha512DigestCommon : LongDigest() {
    init {
        reset()
    }

    override val algorithmName: String get() = ALGORITHM_NAME
    override val digestSize: Int get() = SIZE_BYTES

    override fun build(output: ByteArray, offset: Int): ByteArray {
        finish()

        output.storeLongAt(offset, h1)
        output.storeLongAt(offset + 8, h2)
        output.storeLongAt(offset + 16, h3)
        output.storeLongAt(offset + 24, h4)
        output.storeLongAt(offset + 32, h5)
        output.storeLongAt(offset + 40, h6)
        output.storeLongAt(offset + 48, h7)
        output.storeLongAt(offset + 56, h8)

        reset()
        return output
    }

    override fun reset() {
        super.reset()

        /*
        SHA-512 initial hash value
        The first 64 bits of the fractional parts of the square roots
        of the first eight prime numbers
        */
        h1 = 0x6a09e667f3bcc908L
        h2 = 0xbb67ae8584caa73buL.toLong()
        h3 = 0x3c6ef372fe94f82bL
        h4 = 0xa54ff53a5f1d36f1uL.toLong()
        h5 = 0x510e527fade682d1L
        h6 = 0x9b05688c2b3e6c1fuL.toLong()
        h7 = 0x1f83d9abfb41bd6bL
        h8 = 0x5be0cd19137e2179L
    }

    public companion object {
        public const val ALGORITHM_NAME: String = "SHA-512"
        public const val SIZE_BYTES: Int = 64
        public const val SIZE_BITS: Int = SIZE_BYTES * Byte.SIZE_BITS
    }
}

public inline fun sha512(value: ByteArray): ByteArray = Sha512Digest().apply {
    update(value)
}.build()
