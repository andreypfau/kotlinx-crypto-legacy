import io.github.andreypfau.kotlinx.crypto.aes.AesCipher
import io.github.andreypfau.kotlinx.crypto.cipher.CtrBlockCipher
import io.github.andreypfau.kotlinx.encoding.hex.hex
import kotlin.test.Test
import kotlin.test.assertContentEquals

class AesCtrTest {
    private val COMMON_KEY_128 = hex(
        "2b7e151628aed2a6abf7158809cf4f3c"
    )
    private val COMMON_KEY_192 = hex(
        "8e73b0f7da0e6452c810f32b809079e562f8ead2522c6b7b"
    )
    private val COMMON_KEY_256 = hex(
        "603deb1015ca71be2b73aef0857d7781" +
                "1f352c073b6108d72d9810a30914dff4"
    )
    private val COMMON_COUNTER = hex(
        "f0f1f2f3f4f5f6f7f8f9fafbfcfdfeff"
    )
    private val COMMON_INPUT = hex(
        "6bc1bee22e409f96e93d7e117393172a" +
                "ae2d8a571e03ac9c9eb76fac45af8e51" +
                "30c81c46a35ce411e5fbc1191a0a52ef" +
                "f69f2445df4f9b17ad2b417be66c3710"
    )

    @Test
    fun aes128CtrTest() {
        aesCtrTest(
            key = COMMON_KEY_128,
            iv = COMMON_COUNTER,
            input = COMMON_INPUT,
            output = hex(
                "874d6191b620e3261bef6864990db6ce9806f66b7970fdff8617187bb9fffdff5ae4df3edbd5d35e5b4f09020db03eab1e031dda2fbe03d1792170a0f3009cee"
            )
        )
    }

    @Test
    fun aes192CtrTest() {
        aesCtrTest(
            key = COMMON_KEY_192,
            iv = COMMON_COUNTER,
            input = COMMON_INPUT,
            output = hex(
                "1abc932417521ca24f2b0459fe7e6e0b090339ec0aa6faefd5ccc2c6f4ce8e941e36b26bd1ebc670d1bd1d665620abf74f78a7f6d29809585a97daec58c6b050"
            )
        )
    }

    @Test
    fun aes256CtrTest() {
        aesCtrTest(
            key = COMMON_KEY_256,
            iv = COMMON_COUNTER,
            input = COMMON_INPUT,
            output = hex("601ec313775789a5b7a7f504bbf3d228f443e3ca4d62b59aca84e990cacaf5c52b0930daa23de94ce87017ba2d84988ddfc9c58db67aada613c2dd08457941a6")
        )
    }

    private fun aesCtrTest(
        key: ByteArray,
        iv: ByteArray,
        input: ByteArray,
        output: ByteArray
    ) {
        val aes = AesCipher(key)
        assertContentEquals(output, CtrBlockCipher(aes, iv).encryptToByteArray(input))
    }
}
