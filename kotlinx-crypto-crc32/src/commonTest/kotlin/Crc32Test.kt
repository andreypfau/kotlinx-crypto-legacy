import io.github.andreypfau.kotlinx.crypto.crc32.crc32
import io.github.andreypfau.kotlinx.crypto.crc32.crc32c
import kotlin.test.Test
import kotlin.test.assertEquals

class Crc32Test {

    @Test
    fun testGolden() {
        testGolden(0x0, 0x0, "")
        testGolden(0xe8b7be43, 0xc1d04330, "a")
        testGolden(0x9e83486d, 0xe2a22936, "ab")
        testGolden(0x352441c2, 0x364b3fb7, "abc")
        testGolden(0xed82cd11, 0x92c80a31, "abcd")
        testGolden(0x8587d865, 0xc450d697, "abcde")
        testGolden(0x4b8e39ef, 0x53bceff1, "abcdef")
        testGolden(0x312a6aa6, 0xe627f441, "abcdefg")
        testGolden(0xaeef2a50, 0xa9421b7, "abcdefgh")
        testGolden(0x8da988af, 0x2ddc99fc, "abcdefghi")
        testGolden(0x3981703a, 0xe6599437, "abcdefghij")
        testGolden(0x6b9cdfe7, 0xb2cc01fe, "Discard medicine more than two years old.")
        testGolden(0xc90ef73f, 0xe28207f, "He who has a shady past knows that nice guys finish last.")
        testGolden(0xb902341f, 0xbe93f964, "I wouldn't marry him with a ten foot pole.")
        testGolden(0x42080e8, 0x9e3be0c3, "Free! Free!/A trip/to Mars/for 900/empty jars/Burma Shave")
        testGolden(0x154c6d11, 0xf505ef04, "The days of the digital watch are numbered.  -Tom Stoppard")
        testGolden(0x4c418325, 0x85d3dc82, "Nepal premier won't resign.")
        testGolden(0x33955150, 0xc5142380, "For every action there is an equal and opposite government program.")
        testGolden(0x26216a4b, 0x75eb77dd, "His money is twice tainted: 'taint yours and 'taint mine.")
        testGolden(
            0x1abbe45e,
            0x91ebe9f7,
            "There is no reason for any individual to have a computer in their home. -Ken Olsen, 1977"
        )
        testGolden(
            0xc89a94f7,
            0xf0b1168e,
            "It's a tiny change to the code and not completely disgusting. - Bob Manchek"
        )
        testGolden(0xab3abe14, 0x572b74e2, "size:  a.out:  bad magic")
        testGolden(0xbab102b6, 0x8a58a6d5, "The major problem is with sendmail.  -Mark Horton")
        testGolden(0x999149d7, 0x9c426c50, "Give me a rock, paper and scissors and I will move the world.  CCFestoon")
        testGolden(0x6d52a33c, 0x735400a4, "If the enemy is within range, then so are you.")
        testGolden(0x90631e8d, 0xbec49c95, "It's well we cannot hear the screams/That we create in others' dreams.")
        testGolden(0x78309130, 0xa95a2079, "You remind me of a TV show, but that's all right: I watch it anyway.")
        testGolden(0x7d0a377f, 0xde2e65c5, "C is as portable as Stonehedge!!")
        testGolden(
            0x8c79fd79,
            0x297a88ed,
            "Even if I could be Shakespeare, I think I should still choose to be Faraday. - A. Huxley"
        )
        testGolden(
            0xa20b7167,
            0x66ed1d8b,
            "The fugacity of a constituent in a mixture of gases at a given temperature is proportional to its mole fraction.  Lewis-Randall Rule"
        )
        testGolden(0x8e0bb443, 0xdcded527, "How can you write a big system without C++?  -Paul Glick")
    }

    private fun testGolden(
        ieee: Long,
        castagnoli: Long,
        source: String
    ) {
        val actualIeee = crc32(source.encodeToByteArray())
        assertEquals(ieee.toInt(), actualIeee)
        val actualCastagnoli = crc32c(source.encodeToByteArray())
        assertEquals(castagnoli.toInt(), actualCastagnoli)
    }
}
