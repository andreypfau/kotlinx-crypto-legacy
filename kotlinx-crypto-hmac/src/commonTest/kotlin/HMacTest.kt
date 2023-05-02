import io.github.andreypfau.kotlinx.crypto.digest.Digest
import io.github.andreypfau.kotlinx.crypto.hmac.HMac
import io.github.andreypfau.kotlinx.crypto.sha256.Sha256DigestCommon
import io.github.andreypfau.kotlinx.crypto.sha512.Sha512Digest
import io.github.andreypfau.kotlinx.encoding.hex.hex
import kotlin.test.Test
import kotlin.test.assertContentEquals

class HMacTest {
    @Test
    fun hMacSha256Test() {
        hMacTest(
            digest = Sha256DigestCommon(),
            key = hex(
                "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f"
            ),
            input = "Sample message for keylen=blocklen".encodeToByteArray(),
            output = hex("8bb9a1db9806f20df7f77b82138c7914d174d59e13dc4d0169c9057b133e1d62"),
            size = Sha256DigestCommon.SIZE_BYTES
        )
        hMacTest(
            digest = Sha256DigestCommon(),
            key = hex(
                "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f"
            ),
            input = "Sample message for keylen<blocklen".encodeToByteArray(),
            output = hex("a28cf43130ee696a98f14a37678b56bcfcbdd9e5cf69717fecf5480f0ebdf790"),
            size = Sha256DigestCommon.SIZE_BYTES
        )
        hMacTest(
            digest = Sha256DigestCommon(),
            key = hex("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f404142434445464748494a4b4c4d4e4f505152535455565758595a5b5c5d5e5f60616263"),
            input = "Sample message for keylen=blocklen".encodeToByteArray(),
            output = hex("bdccb6c72ddeadb500ae768386cb38cc41c63dbb0878ddb9c7a38a431b78378d"),
            size = Sha256DigestCommon.SIZE_BYTES
        )
        hMacTest(
            digest = Sha256DigestCommon(),
            key = byteArrayOf(),
            input = "message".encodeToByteArray(),
            output = hex("eb08c1f56d5ddee07f7bdf80468083da06b64cf4fac64fe3a90883df5feacae4"),
            size = Sha256DigestCommon.SIZE_BYTES
        )
    }

    @Test
    fun hMacSha512Test() {
        hMacTest(
            digest = Sha512Digest(),
            key = hex("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f404142434445464748494a4b4c4d4e4f505152535455565758595a5b5c5d5e5f606162636465666768696a6b6c6d6e6f707172737475767778797a7b7c7d7e7f"),
            input = "Sample message for keylen=blocklen".encodeToByteArray(),
            output = hex("fc25e240658ca785b7a811a8d3f7b4ca48cfa26a8a366bf2cd1f836b05fcb024bd36853081811d6cea4216ebad79da1cfcb95ea4586b8a0ce356596a55fb1347"),
            size = Sha512Digest.SIZE_BYTES
        )
        hMacTest(
            digest = Sha512Digest(),
            key = hex("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f"),
            input = "Sample message for keylen<blocklen".encodeToByteArray(),
            output = hex(
                "fd44c18bda0bb0a6ce0e82b031bf2818" +
                        "f6539bd56ec00bdc10a8a2d730b3634de2545d639b0f2cf7" +
                        "10d0692c72a1896f1f211c2b922d1a96c392e07e7ea9fedc"
            ),
            size = Sha512Digest.SIZE_BYTES
        )
        hMacTest(
            digest = Sha512Digest(),
            key = hex("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f404142434445464748494a4b4c4d4e4f505152535455565758595a5b5c5d5e5f606162636465666768696a6b6c6d6e6f707172737475767778797a7b7c7d7e7f808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9fa0a1a2a3a4a5a6a7a8a9aaabacadaeafb0b1b2b3b4b5b6b7b8b9babbbcbdbebfc0c1c2c3c4c5c6c7"),
            input = "Sample message for keylen=blocklen".encodeToByteArray(),
            output = hex("d93ec8d2de1ad2a9957cb9b83f14e76ad6b5e0cce285079a127d3b14bccb7aa7286d4ac0d4ce64215f2bc9e6870b33d97438be4aaa20cda5c5a912b48b8e27f3"),
            size = Sha512Digest.SIZE_BYTES
        )
        hMacTest(
            digest = Sha512Digest(),
            key = byteArrayOf(),
            input = "message".encodeToByteArray(),
            output = hex("08fce52f6395d59c2a3fb8abb281d74ad6f112b9a9c787bcea290d94dadbc82b2ca3e5e12bf2277c7fedbb0154d5493e41bb7459f63c8e39554ea3651b812492"),
            size = Sha512Digest.SIZE_BYTES
        )
    }

    private fun hMacTest(
        digest: Digest,
        key: ByteArray,
        input: ByteArray,
        output: ByteArray,
        size: Int
    ) {
        val hMac = HMac(digest, key)
        check(hMac.macSize == size) {
            "size: expected: $size, actual: ${hMac.macSize}"
        }
        for (j in 0 until 4) {
            hMac.update(input)

            val sum = hMac.build()
            assertContentEquals(output, sum, "expected: ${hex(output)}\nactual:   ${hex(sum)}")
        }
    }
}
