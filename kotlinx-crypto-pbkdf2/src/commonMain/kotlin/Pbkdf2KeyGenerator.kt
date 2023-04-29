package io.github.andreypfau.kotlinx.crypto.pbkdf2

import io.github.andreypfau.kotlinx.crypto.digest.Digest
import io.github.andreypfau.kotlinx.crypto.hmac.HMac
import kotlin.experimental.xor

public class Pbkdf2KeyGenerator(
    private val hMac: HMac,
    password: ByteArray,
    salt: ByteArray,
    private val iterationCount: Int
) {
    public constructor(digest: Digest, password: ByteArray, salt: ByteArray, iterationCount: Int) : this(
        HMac(digest), password, salt, iterationCount
    )

    private val password = password.copyOf()
    private val salt = salt.copyOf()
    private val state = ByteArray(hMac.macSize)

    public fun generateDerivedKeyToByteArray(
        keyLength: Int
    ): ByteArray {
        val dk = ByteArray(keyLength)
        generateDerivedKeyIntoByteArray(keyLength, dk)
        return dk
    }

    public fun generateDerivedKeyIntoByteArray(
        keyLength: Int,
        destination: ByteArray,
        destinationOffset: Int = 0
    ): Int {
        val hashLength = hMac.macSize
        val blocksCount = (keyLength + hashLength - 1) / hashLength
        val dk = generateDerivedKey(blocksCount)
        dk.copyInto(destination, destinationOffset, 0, keyLength)
        return keyLength
    }

    private fun generateDerivedKey(
        blocksCount: Int
    ): ByteArray {
        val hashLength = hMac.macSize
        val dk = ByteArray(blocksCount * hashLength)
        val iBuf = ByteArray(4)
        var dkOffset = 0

        hMac.init(password)
        for (i in 1..blocksCount) {
            iBuf[0] = (i ushr 24).toByte()
            iBuf[1] = (i ushr 16).toByte()
            iBuf[2] = (i ushr 8).toByte()
            iBuf[3] = i.toByte()

            if (salt.isNotEmpty()) {
                hMac.update(salt)
            }
            hMac.update(iBuf)
            hMac.build(state)

            state.copyInto(dk, dkOffset)

            for (count in 1 until iterationCount) {
                hMac.update(state)
                hMac.build(state)
                for (j in state.indices) {
                    dk[dkOffset + j] = (dk[dkOffset + j] xor state[j])
                }
            }

            dkOffset += hashLength
        }

        return dk
    }
}

public inline fun pbkdb2(
    digest: Digest,
    password: ByteArray,
    salt: ByteArray,
    iterationCount: Int,
    keyLength: Int
): ByteArray = Pbkdf2KeyGenerator(digest, password, salt, iterationCount).run {
    generateDerivedKeyToByteArray(keyLength)
}
