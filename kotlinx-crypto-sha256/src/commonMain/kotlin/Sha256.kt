package io.github.andreypfau.kotlinx.crypto.sha256

public fun sha256(byteArray: ByteArray): ByteArray {
    val digest = Sha256Digest()
    digest += byteArray
    return digest.build()
}
