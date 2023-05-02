package io.github.andreypfau.kotlinx.crypto.aes

import io.github.andreypfau.kotlinx.crypto.cipher.BlockCipher

public actual class AesCipher actual constructor(key: ByteArray) : BlockCipher by AesCipherCommon(key)
