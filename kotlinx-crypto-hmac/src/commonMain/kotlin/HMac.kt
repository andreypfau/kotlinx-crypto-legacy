package io.github.andreypfau.kotlinx.crypto.hmac

import io.github.andreypfau.kotlinx.crypto.digest.Digest
import io.github.andreypfau.kotlinx.crypto.mac.Mac
import kotlin.experimental.xor

/**
 * HMAC implementation based on RFC2104
 *
 * H(K XOR opad, H(K XOR ipad, text))
 */
public class HMac private constructor(
    private val digest: Digest,
    private val blockSize: Int
) : Mac {
    public constructor(digest: Digest) : this(digest, byteLength(digest))
    public constructor(digest: Digest, key: ByteArray) : this(digest) {
        init(key)
    }

    public override val algorithmName: String get() = "HMAC/${digest.algorithmName}"
    public override val macSize: Int get() = digestSize

    private val digestSize = digest.digestSize
    private val inputPad = ByteArray(blockSize)
    private val outputBuf = ByteArray(blockSize + digestSize)

    public override fun init(key: ByteArray): HMac = apply {
        digest.reset()
        var keyLength = key.size

        if (keyLength > blockSize) {
            digest.update(key)
            digest.build(inputPad)
            keyLength = digestSize
        } else {
            key.copyInto(inputPad)
        }

        inputPad.fill(0, keyLength, inputPad.size)
        inputPad.copyInto(outputBuf)

        xorPad(inputPad, 0, blockSize, IPAD)
        xorPad(outputBuf, 0, blockSize, OPAD)

        digest.update(inputPad)
    }

    public override fun update(input: ByteArray, offset: Int, length: Int) {
        digest.update(input, offset, length)
    }

    public override fun build(output: ByteArray, offset: Int): ByteArray = output.apply {
        digest.build(outputBuf, blockSize)
        digest.update(outputBuf)
        digest.build(output, offset)
        outputBuf.fill(0, blockSize, outputBuf.size)
        digest.update(inputPad)
    }

    public override fun reset() {
        digest.reset()
        digest.update(inputPad)
    }

    public companion object {
        private const val IPAD = 0x36.toByte()
        private const val OPAD = 0x5C.toByte()

        private fun byteLength(digest: Digest) = when (digest.algorithmName) {
            "MD2" -> 16
            "MD4", "MD5" -> 64
            "SHA-1", "SHA-224", "SHA-256" -> 64
            "SHA-384", "SHA-512" -> 128
            "RIPEMD128", "RIPEMD160" -> 64
            "Tiger", "Whirlpool" -> 64
            "GOST3411" -> 32
            else -> throw IllegalArgumentException("Unsupported digest algorithm: ${digest.algorithmName}")
        }

        private fun xorPad(pad: ByteArray, offset: Int, length: Int, value: Byte) {
            for (i in offset until offset + length) {
                pad[i] = pad[i] xor value
            }
        }
    }
}

public inline fun hMac(digest: Digest, key: ByteArray, value: ByteArray): ByteArray =
    HMac(digest, key).run {
        update(value)
        build()
    }
