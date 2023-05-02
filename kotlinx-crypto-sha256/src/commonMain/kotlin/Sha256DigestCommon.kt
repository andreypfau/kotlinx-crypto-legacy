package io.github.andreypfau.kotlinx.crypto.sha256

import io.github.andreypfau.kotlinx.crypto.digest.GeneralDigest
import io.github.andreypfau.kotlinx.encoding.binary.Binary.storeIntAt

/**
 * FIPS 180-2 implementation of SHA-256.
 *
 * ```
 *         block  word  digest
 * SHA-1   512    32    160
 * SHA-256 512    32    256
 * SHA-384 1024   64    384
 * SHA-512 1024   64    512
 * ```
 */
public open class Sha256DigestCommon : GeneralDigest() {
    private var h1 = 0
    private var h2 = 0
    private var h3 = 0
    private var h4 = 0
    private var h5 = 0
    private var h6 = 0
    private var h7 = 0
    private var h8 = 0
    private val x = IntArray(64)
    private var xOff = 0

    init {
        reset()
    }

    override val algorithmName: String get() = ALGORITHM_NAME
    override val digestSize: Int get() = SIZE_BYTES

    override fun build(output: ByteArray, offset: Int): ByteArray {
        finish()

        output.storeIntAt(offset, h1)
        output.storeIntAt(offset + 4, h2)
        output.storeIntAt(offset + 8, h3)
        output.storeIntAt(offset + 12, h4)
        output.storeIntAt(offset + 16, h5)
        output.storeIntAt(offset + 20, h6)
        output.storeIntAt(offset + 24, h7)
        output.storeIntAt(offset + 28, h8)

        reset()
        return output
    }

    override fun reset() {
        super.reset()

        /**
         * SHA-256 initial hash value
         * The first 32 bits of the fractional parts of the square roots
         * of the first eight prime numbers
         */
        h1 = 0x6a09e667
        h2 = 0xbb67ae85.toInt()
        h3 = 0x3c6ef372
        h4 = 0xa54ff53a.toInt()
        h5 = 0x510e527f
        h6 = 0x9b05688c.toInt()
        h7 = 0x1f83d9ab
        h8 = 0x5be0cd19

        xOff = 0
        x.fill(0)
    }

    protected override fun processWord(input: ByteArray, offset: Int) {
        var n = input[offset].toInt() shl 24
        n = n or ((input[offset + 1].toInt() and 0xFF) shl 16)
        n = n or ((input[offset + 2].toInt() and 0xFF) shl 8)
        n = n or (input[offset + 3].toInt() and 0xFF)
        x[xOff] = n
        if (++xOff == 16) {
            processBlock()
        }
    }

    protected override fun processLength(bitLength: Long) {
        if (xOff > 14) {
            processBlock()
        }
        x[14] = (bitLength ushr 32).toInt()
        x[15] = (bitLength and 0xffffffff).toInt()
    }

    protected override fun processBlock() {
        // expand 16 word block into 64 word blocks.
        for (t in 16 until 64) {
            x[t] = Theta1(x[t - 2]) + x[t - 7] + Theta0(x[t - 15]) + x[t - 16]
        }

        // set up working variables.
        var a = h1
        var b = h2
        var c = h3
        var d = h4
        var e = h5
        var f = h6
        var g = h7
        var h = h8

        var t = 0
        for (i in 0 until 8) {
            // t = 8 * i
            h += Sum1(e) + Ch(e, f, g) + k[t] + x[t]
            d += h
            h += Sum0(a) + Maj(a, b, c)
            ++t

            // t = 8 * i + 1
            g += Sum1(d) + Ch(d, e, f) + k[t] + x[t]
            c += g
            g += Sum0(h) + Maj(h, a, b)
            ++t

            // t = 8 * i + 2
            f += Sum1(c) + Ch(c, d, e) + k[t] + x[t]
            b += f
            f += Sum0(g) + Maj(g, h, a)
            ++t

            // t = 8 * i + 3
            e += Sum1(b) + Ch(b, c, d) + k[t] + x[t]
            a += e
            e += Sum0(f) + Maj(f, g, h)
            ++t

            // t = 8 * i + 4
            d += Sum1(a) + Ch(a, b, c) + k[t] + x[t]
            h += d
            d += Sum0(e) + Maj(e, f, g)
            ++t

            // t = 8 * i + 5
            c += Sum1(h) + Ch(h, a, b) + k[t] + x[t]
            g += c
            c += Sum0(d) + Maj(d, e, f)
            ++t

            // t = 8 * i + 6
            b += Sum1(g) + Ch(g, h, a) + k[t] + x[t]
            f += b
            b += Sum0(c) + Maj(c, d, e)
            ++t

            // t = 8 * i + 7
            a += Sum1(f) + Ch(f, g, h) + k[t] + x[t]
            e += a
            a += Sum0(b) + Maj(b, c, d)
            ++t
        }

        h1 += a
        h2 += b
        h3 += c
        h4 += d
        h5 += e
        h6 += f
        h7 += g
        h8 += h

        // reset the offset and clean out the word buffer.
        xOff = 0
        x.fill(0)
    }

    public companion object {
        public const val ALGORITHM_NAME: String = "SHA-256"
        public const val SIZE_BYTES: Int = 32
        public const val SIZE_BITS: Int = SIZE_BYTES * Byte.SIZE_BITS

        /**
         * SHA-256 Constants
         * (represent the first 32 bits of the fractional parts of the
         * cube roots of the first sixty-four prime numbers)
         */
        private val k = intArrayOf(
            0x428a2f98,
            0x71374491,
            0xb5c0fbcf.toInt(),
            0xe9b5dba5.toInt(),
            0x3956c25b,
            0x59f111f1,
            0x923f82a4.toInt(),
            0xab1c5ed5.toInt(),
            0xd807aa98.toInt(),
            0x12835b01,
            0x243185be,
            0x550c7dc3,
            0x72be5d74,
            0x80deb1fe.toInt(),
            0x9bdc06a7.toInt(),
            0xc19bf174.toInt(),
            0xe49b69c1.toInt(),
            0xefbe4786.toInt(),
            0x0fc19dc6,
            0x240ca1cc,
            0x2de92c6f,
            0x4a7484aa,
            0x5cb0a9dc,
            0x76f988da,
            0x983e5152.toInt(),
            0xa831c66d.toInt(),
            0xb00327c8.toInt(),
            0xbf597fc7.toInt(),
            0xc6e00bf3.toInt(),
            0xd5a79147.toInt(),
            0x06ca6351,
            0x14292967,
            0x27b70a85,
            0x2e1b2138,
            0x4d2c6dfc,
            0x53380d13,
            0x650a7354,
            0x766a0abb,
            0x81c2c92e.toInt(),
            0x92722c85.toInt(),
            0xa2bfe8a1.toInt(),
            0xa81a664b.toInt(),
            0xc24b8b70.toInt(),
            0xc76c51a3.toInt(),
            0xd192e819.toInt(),
            0xd6990624.toInt(),
            0xf40e3585.toInt(),
            0x106aa070,
            0x19a4c116,
            0x1e376c08,
            0x2748774c,
            0x34b0bcb5,
            0x391c0cb3,
            0x4ed8aa4a,
            0x5b9cca4f,
            0x682e6ff3,
            0x748f82ee,
            0x78a5636f,
            0x84c87814.toInt(),
            0x8cc70208.toInt(),
            0x90befffa.toInt(),
            0xa4506ceb.toInt(),
            0xbef9a3f7.toInt(),
            0xc67178f2u.toInt(),
        )

        private fun Ch(x: Int, y: Int, z: Int): Int = (x and y) xor (x.inv() and z)

        private fun Maj(x: Int, y: Int, z: Int): Int = (x and y) xor (x and z) xor (y and z)

        private fun Sum0(x: Int): Int =
            ((x ushr 2) or (x shl 30)) xor ((x ushr 13) or (x shl 19)) xor ((x ushr 22) or (x shl 10))

        private fun Sum1(x: Int): Int =
            ((x ushr 6) or (x shl 26)) xor ((x ushr 11) or (x shl 21)) xor ((x ushr 25) or (x shl 7))

        private fun Theta0(x: Int): Int =
            ((x ushr 7) or (x shl 25)) xor ((x ushr 18) or (x shl 14)) xor (x ushr 3)

        private fun Theta1(x: Int): Int =
            ((x ushr 17) or (x shl 15)) xor ((x ushr 19) or (x shl 13)) xor (x ushr 10)
    }
}
