package io.github.andreypfau.kotlinx.crypto.cipher

public interface StreamCipher {
    public fun encryptToByteArray(
        source: ByteArray,
        startIndex: Int = 0,
        endIndex: Int = source.size
    ): ByteArray {
        val destination = ByteArray(endIndex - startIndex)
        encryptIntoByteArray(source, destination, startIndex = startIndex, endIndex = endIndex)
        return destination
    }

    public fun encryptIntoByteArray(
        source: ByteArray,
        destination: ByteArray,
        destinationOffset: Int = 0,
        startIndex: Int = 0,
        endIndex: Int = source.size
    ): Int
}
