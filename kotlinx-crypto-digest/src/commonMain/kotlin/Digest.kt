package io.github.andreypfau.kotlinx.crypto.digest

public interface Digest {
    public val algorithmName: String
    public val digestSize: Int

    public fun update(input: ByteArray): Unit =
        update(input, 0, input.size)

    public fun update(input: ByteArray, offset: Int, length: Int)

    public operator fun plusAssign(input: ByteArray): Unit = update(input)

    public fun build(): ByteArray = build(ByteArray(digestSize))

    public fun build(output: ByteArray): ByteArray = build(output, 0)

    public fun build(output: ByteArray, offset: Int): ByteArray

    public fun reset()
}
