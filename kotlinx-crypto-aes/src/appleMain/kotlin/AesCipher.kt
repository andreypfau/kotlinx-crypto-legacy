package io.github.andreypfau.kotlinx.crypto.aes

import io.github.andreypfau.kotlinx.crypto.cipher.BlockCipher
import kotlinx.cinterop.*
import platform.CoreCrypto.*
import platform.posix.size_tVar

public actual class AesCipher actual constructor(key: ByteArray) : BlockCipher {
    init {
        require(key.size == 16 || key.size == 24 || key.size == 32) {
            "invalid key size, expected: 16/24/32, actual: ${key.size}"
        }
    }

    override val algorithmName: String get() = AesCipherCommon.ALGORITHM_NAME
    override val blockSize: Int get() = AesCipherCommon.BLOCK_SIZE
    private val keyData = key.copyOf().refTo(0)
    private val keyLength = key.size

    override fun encryptIntoByteArray(
        source: ByteArray,
        destination: ByteArray,
        destinationOffset: Int,
        startIndex: Int,
        endIndex: Int
    ): Int = memScoped {
        val bytesWriten = cValue<size_tVar>()

        val status = CCCrypt(
            op = kCCEncrypt,
            alg = kCCAlgorithmAES128,
            options = kCCOptionECBMode,
            key = keyData,
            keyLength = keyLength.convert(),
            iv = null,
            dataIn = source.refTo(startIndex),
            dataInLength = (endIndex - startIndex).convert(),
            dataOut = destination.refTo(destinationOffset),
            dataOutAvailable = (destination.size - destinationOffset).convert(),
            dataOutMoved = bytesWriten
        )
        check(status == kCCSuccess) {
            val errorMessage = when (status) {
                kCCParamError -> "Illegal parameter value."
                kCCBufferTooSmall -> "Insufficent buffer provided for specified operation."
                kCCMemoryFailure -> "Memory allocation failure."
                kCCAlignmentError -> "Input size was not aligned properly."
                kCCDecodeError -> "Input data did not decode or decrypt properly."
                kCCUnimplemented -> "Function not implemented for the current algorithm."
                else -> "Unknown error: $status"
            }
            throw RuntimeException(errorMessage)
        }
        bytesWriten.ptr[0].toInt()
    }
}
