import io.github.andreypfau.kotlinx.crypto.digest.Digest
import io.github.andreypfau.kotlinx.crypto.pbkdf2.pbkdb2
import io.github.andreypfau.kotlinx.crypto.sha256.Sha256DigestCommon
import io.github.andreypfau.kotlinx.encoding.hex.hex
import kotlin.test.Test
import kotlin.test.assertContentEquals

class Pbkdf2Test {
    @Test
    fun pbkdf2HmacSha256Test1() = pbkdf2Test(
        digest = Sha256DigestCommon(),
        password = "password".encodeToByteArray(),
        salt = "salt".encodeToByteArray(),
        iterationCount = 1,
        output = hex("120fb6cffcf8b32c43e7225256c4f837a86548c9")
    )

    @Test
    fun pbkdf2HmacSha256Test2() = pbkdf2Test(
        digest = Sha256DigestCommon(),
        password = "password".encodeToByteArray(),
        salt = "salt".encodeToByteArray(),
        iterationCount = 2,
        output = hex("ae4d0c95af6b46d32d0adff928f06dd02a303f8e")
    )

    @Test
    fun pbkdf2HmacSha256Test3() = pbkdf2Test(
        digest = Sha256DigestCommon(),
        password = "password".encodeToByteArray(),
        salt = "salt".encodeToByteArray(),
        iterationCount = 4096,
        output = hex("c5e478d59288c841aa530db6845c4c8d962893a0")
    )

    @Test
    fun pbkdf2HmacSha256Test4() = pbkdf2Test(
        digest = Sha256DigestCommon(),
        password = "passwordPASSWORDpassword".encodeToByteArray(),
        salt = "saltSALTsaltSALTsaltSALTsaltSALTsalt".encodeToByteArray(),
        iterationCount = 4096,
        output = hex("348c89dbcbd32b2f32d814b8116e84cf2b17347ebc1800181c")
    )

    @Test
    fun pbkdf2HmacSha256Test5() = pbkdf2Test(
        digest = Sha256DigestCommon(),
        password = "pass\u0000word".encodeToByteArray(),
        salt = "sa\u0000lt".encodeToByteArray(),
        iterationCount = 4096,
        output = hex("89b69d0516f829893c696226650a8687")
    )

    private fun pbkdf2Test(
        digest: Digest,
        password: ByteArray,
        salt: ByteArray,
        iterationCount: Int,
        output: ByteArray
    ) {
        val actual = pbkdb2(
            digest = digest,
            password = password,
            salt = salt,
            iterationCount = iterationCount,
            keyLength = output.size
        )
        assertContentEquals(output, actual, "expected: ${hex(output)}\nactual:   ${hex(actual)}")
    }
}
