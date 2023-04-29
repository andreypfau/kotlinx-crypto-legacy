import io.github.andreypfau.kotlinx.crypto.aes.AesCipher
import io.github.andreypfau.kotlinx.crypto.aes.aesExpandKey
import io.github.andreypfau.kotlinx.encoding.hex.hex
import kotlin.test.Test
import kotlin.test.assertContentEquals

class AesCipherTest {
    @Test
    fun expandKey128Test() {
        // A.1.  Expansion of a 128-bit Cipher Key
        keysTest(
            key = hex("2b7e151628aed2a6abf7158809cf4f3c"),
            encrypt = uintArrayOf(
                0x2b7e1516u, 0x28aed2a6u, 0xabf71588u, 0x09cf4f3cu,
                0xa0fafe17u, 0x88542cb1u, 0x23a33939u, 0x2a6c7605u,
                0xf2c295f2u, 0x7a96b943u, 0x5935807au, 0x7359f67fu,
                0x3d80477du, 0x4716fe3eu, 0x1e237e44u, 0x6d7a883bu,
                0xef44a541u, 0xa8525b7fu, 0xb671253bu, 0xdb0bad00u,
                0xd4d1c6f8u, 0x7c839d87u, 0xcaf2b8bcu, 0x11f915bcu,
                0x6d88a37au, 0x110b3efdu, 0xdbf98641u, 0xca0093fdu,
                0x4e54f70eu, 0x5f5fc9f3u, 0x84a64fb2u, 0x4ea6dc4fu,
                0xead27321u, 0xb58dbad2u, 0x312bf560u, 0x7f8d292fu,
                0xac7766f3u, 0x19fadc21u, 0x28d12941u, 0x575c006eu,
                0xd014f9a8u, 0xc9ee2589u, 0xe13f0cc8u, 0xb6630ca6u,
            ).asIntArray(),
            decrypt = uintArrayOf(
                0xd014f9a8u, 0xc9ee2589u, 0xe13f0cc8u, 0xb6630ca6u,
                0xc7b5a63u, 0x1319eafeu, 0xb0398890u, 0x664cfbb4u,
                0xdf7d925au, 0x1f62b09du, 0xa320626eu, 0xd6757324u,
                0x12c07647u, 0xc01f22c7u, 0xbc42d2f3u, 0x7555114au,
                0x6efcd876u, 0xd2df5480u, 0x7c5df034u, 0xc917c3b9u,
                0x6ea30afcu, 0xbc238cf6u, 0xae82a4b4u, 0xb54a338du,
                0x90884413u, 0xd280860au, 0x12a12842u, 0x1bc89739u,
                0x7c1f13f7u, 0x4208c219u, 0xc021ae48u, 0x969bf7bu,
                0xcc7505ebu, 0x3e17d1eeu, 0x82296c51u, 0xc9481133u,
                0x2b3708a7u, 0xf262d405u, 0xbc3ebdbfu, 0x4b617d62u,
                0x2b7e1516u, 0x28aed2a6u, 0xabf71588u, 0x9cf4f3cu,
            ).asIntArray()
        )
    }

    @Test
    fun expandKey192Test() {
        // A.2.  Expansion of a 192-bit Cipher Key
        keysTest(
            key = hex("8e73b0f7da0e6452c810f32b809079e562f8ead2522c6b7b"),
            encrypt = uintArrayOf(
                0x8e73b0f7u, 0xda0e6452u, 0xc810f32bu, 0x809079e5u,
                0x62f8ead2u, 0x522c6b7bu, 0xfe0c91f7u, 0x2402f5a5u,
                0xec12068eu, 0x6c827f6bu, 0x0e7a95b9u, 0x5c56fec2u,
                0x4db7b4bdu, 0x69b54118u, 0x85a74796u, 0xe92538fdu,
                0xe75fad44u, 0xbb095386u, 0x485af057u, 0x21efb14fu,
                0xa448f6d9u, 0x4d6dce24u, 0xaa326360u, 0x113b30e6u,
                0xa25e7ed5u, 0x83b1cf9au, 0x27f93943u, 0x6a94f767u,
                0xc0a69407u, 0xd19da4e1u, 0xec1786ebu, 0x6fa64971u,
                0x485f7032u, 0x22cb8755u, 0xe26d1352u, 0x33f0b7b3u,
                0x40beeb28u, 0x2f18a259u, 0x6747d26bu, 0x458c553eu,
                0xa7e1466cu, 0x9411f1dfu, 0x821f750au, 0xad07d753u,
                0xca400538u, 0x8fcc5006u, 0x282d166au, 0xbc3ce7b5u,
                0xe98ba06fu, 0x448c773cu, 0x8ecc7204u, 0x01002202u,
            ).asIntArray()
        )
    }

    @Test
    fun expandKey256Test() {
        // A.3.  Expansion of a 256-bit Cipher Key
        keysTest(
            key = hex("603deb1015ca71be2b73aef0857d77811f352c073b6108d72d9810a30914dff4"),
            encrypt = uintArrayOf(
                0x603deb10u, 0x15ca71beu, 0x2b73aef0u, 0x857d7781u,
                0x1f352c07u, 0x3b6108d7u, 0x2d9810a3u, 0x0914dff4u,
                0x9ba35411u, 0x8e6925afu, 0xa51a8b5fu, 0x2067fcdeu,
                0xa8b09c1au, 0x93d194cdu, 0xbe49846eu, 0xb75d5b9au,
                0xd59aecb8u, 0x5bf3c917u, 0xfee94248u, 0xde8ebe96u,
                0xb5a9328au, 0x2678a647u, 0x98312229u, 0x2f6c79b3u,
                0x812c81adu, 0xdadf48bau, 0x24360af2u, 0xfab8b464u,
                0x98c5bfc9u, 0xbebd198eu, 0x268c3ba7u, 0x09e04214u,
                0x68007bacu, 0xb2df3316u, 0x96e939e4u, 0x6c518d80u,
                0xc814e204u, 0x76a9fb8au, 0x5025c02du, 0x59c58239u,
                0xde136967u, 0x6ccc5a71u, 0xfa256395u, 0x9674ee15u,
                0x5886ca5du, 0x2e2f31d7u, 0x7e0af1fau, 0x27cf73c3u,
                0x749c47abu, 0x18501ddau, 0xe2757e4fu, 0x7401905au,
                0xcafaaae3u, 0xe4d59b34u, 0x9adf6aceu, 0xbd10190du,
                0xfe4890d1u, 0xe6188d0bu, 0x046df344u, 0x706c631eu,
            ).asIntArray()
        )
    }

    @Test
    fun encryptAesTest() {
        // Appendix B.
        encryptTest(
            key = hex("2b7e151628aed2a6abf7158809cf4f3c"),
            input = hex("3243f6a8885a308d313198a2e0370734"),
            output = hex("3925841d02dc09fbdc118597196a0b32")
        )
    }

    @Test
    fun encryptAes128Test() {
        // Appendix C.1.  AES-128
        encryptTest(
            key = hex("000102030405060708090a0b0c0d0e0f"),
            input = hex("00112233445566778899aabbccddeeff"),
            output = hex("69c4e0d86a7b0430d8cdb78070b4c55a")
        )
    }

    @Test
    fun encryptAes192Test() {
        // Appendix C.2.  AES-192
        encryptTest(
            key = hex("000102030405060708090a0b0c0d0e0f1011121314151617"),
            input = hex("00112233445566778899aabbccddeeff"),
            output = hex("dda97ca4864cdfe06eaf70a0ec0d7191")
        )
    }

    @Test
    fun encryptAes256Test() {
        // Appendix C.3.  AES-256
        encryptTest(
            key = hex("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f"),
            input = hex("00112233445566778899aabbccddeeff"),
            output = hex("8ea2b7ca516745bfeafc49904b496089")
        )
    }

    private fun keysTest(
        key: ByteArray,
        encrypt: IntArray,
        decrypt: IntArray = intArrayOf()
    ) {
        val actualEncrypt = IntArray(encrypt.size)
        val actualDecrypt = IntArray(decrypt.size)
        aesExpandKey(key, actualEncrypt, actualDecrypt)
        assertContentEquals(encrypt, actualEncrypt)
        assertContentEquals(decrypt, actualDecrypt)
    }

    private fun encryptTest(
        key: ByteArray,
        input: ByteArray,
        output: ByteArray
    ) {
        val cipher = AesCipher(key = key, decrypt = false)
        val actual = cipher.encryptToByteArray(input)
        assertContentEquals(
            output,
            actual
        )
    }
}
