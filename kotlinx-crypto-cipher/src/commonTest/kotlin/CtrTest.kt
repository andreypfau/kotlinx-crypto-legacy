class CtrTest {
//    @Test
//    fun testCtr() {
//        var size = 64
//        while (size <= 1024) {
//            val iv = ByteArray(size)
//            val ctr = CtrBlockCipher(NopCipher(size), iv)
//            val src = ByteArray(1024) { 0xFF.toByte() }
//            val expected = src.copyOf()
//
//            var counter = ByteArray(size)
//            for (i in 1 until expected.size / size) {
//                inc(counter)
//                xor(expected, i*size, (i+1)*size, counter)
//            }
//            val dest = ByteArray(1024)
//            ctr.processBytes(
//                dest,
//                src
//            )
//
//            size *= 2
//        }
//    }
//
//    private fun inc(bytes: ByteArray) {
//        var i = bytes.size - 1
//        while (i >= 0) {
//            bytes[i]++
//            if (bytes[i].toInt() != 0) {
//                break
//            }
//            i++
//        }
//    }
//
//    private fun xor(a: ByteArray, aStart: Int, aEnd: Int, b: ByteArray) {
//        val length = aEnd - aStart
//        for (i in 0 until length) {
//            a[i] = a[aStart + i] xor b[i]
//        }
//    }
//
//    class NopCipher(
//        override val blockSize: Int
//    ) : BlockCipher {
//        override val algorithmName: String get() = "NOP"
//
//        override fun encrypt(
//            destination: ByteArray,
//            destinationOffset: Int,
//            source: ByteArray,
//            startIndex: Int,
//            endIndex: Int
//        ) {
//            source.copyInto(
//                destination,
//                destinationOffset,
//                startIndex,
//                endIndex
//            )
//        }
//    }
}
