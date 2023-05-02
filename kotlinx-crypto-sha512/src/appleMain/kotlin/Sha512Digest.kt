package io.github.andreypfau.kotlinx.crypto.sha512

import io.github.andreypfau.kotlinx.crypto.digest.Digest
import kotlinx.cinterop.*
import platform.CoreCrypto.CC_SHA512_CTX
import platform.CoreCrypto.CC_SHA512_Final
import platform.CoreCrypto.CC_SHA512_Init
import platform.CoreCrypto.CC_SHA512_Update
import kotlin.native.internal.createCleaner

public actual class Sha512Digest : Digest {
    override val algorithmName: String get() = Sha512DigestCommon.ALGORITHM_NAME
    override val digestSize: Int get() = Sha512DigestCommon.SIZE_BYTES

    private var context = init()

    @OptIn(ExperimentalStdlibApi::class)
    private val cleaner = createCleaner(this) {
        nativeHeap.free(context)
    }

    private fun init(): CC_SHA512_CTX {
        return nativeHeap.alloc<CC_SHA512_CTX>().also {
            CC_SHA512_Init(it.ptr)
        }
    }

    override fun update(input: Byte) {
        CC_SHA512_Update(context.ptr, cValuesOf(input), 1)
    }

    override fun update(input: ByteArray, offset: Int, length: Int) {
        if (length == 0) return
        CC_SHA512_Update(context.ptr, input.refTo(offset), length.toUInt())
    }

    override fun build(output: ByteArray, offset: Int): ByteArray {
        CC_SHA512_Final(output.asUByteArray().refTo(offset), context.ptr)
        return output
    }

    override fun reset() {
        context = init()
    }
}
