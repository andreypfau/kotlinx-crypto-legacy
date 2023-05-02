package io.github.andreypfau.kotlinx.crypto.sha512

import io.github.andreypfau.kotlinx.crypto.digest.Digest

public actual class Sha512Digest : Digest by Sha512DigestCommon()
