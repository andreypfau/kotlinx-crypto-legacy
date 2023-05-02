package io.github.andreypfau.kotlinx.crypto.sha256

import io.github.andreypfau.kotlinx.crypto.digest.Digest

public actual class Sha256Digest : Digest by Sha256DigestCommon()
