package io.github.andreypfau.kotlinx.crypto.sha256

import io.github.andreypfau.kotlinx.crypto.digest.Digest
import kotlinx.cinterop.*
import platform.CoreCrypto.CC_SHA256_CTX
import platform.CoreCrypto.CC_SHA256_Final
import platform.CoreCrypto.CC_SHA256_Init
import platform.CoreCrypto.CC_SHA256_Update
import kotlin.native.internal.createCleaner

public actual class Sha256Digest : Digest {
    override val algorithmName: String get() = Sha256DigestCommon.ALGORITHM_NAME
    override val digestSize: Int get() = Sha256DigestCommon.SIZE_BYTES
    private var context = init()

    @OptIn(ExperimentalStdlibApi::class)
    private val cleaner = createCleaner(this) {
        nativeHeap.free(context)
    }

    private fun init(): CC_SHA256_CTX {
        return nativeHeap.alloc<CC_SHA256_CTX>().also {
            CC_SHA256_Init(it.ptr)
        }
    }

    override fun update(input: Byte) {
        CC_SHA256_Update(context.ptr, cValuesOf(input), 1)
    }

    override fun update(input: ByteArray, offset: Int, length: Int) {
        CC_SHA256_Update(context.ptr, input.refTo(offset), length.toUInt())
    }

    override fun build(output: ByteArray, offset: Int): ByteArray {
        CC_SHA256_Final(output.asUByteArray().refTo(offset), context.ptr)
        return output
    }

    override fun reset() {
        context = init()
    }
}
