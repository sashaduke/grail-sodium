# grail-sodium

Typed [Grail](https://github.com/graillang/grail) bindings to the installed
[libsodium](https://libsodium.org). Every primitive runs inside the audited C library; this
package only checks lengths, allocates outputs and passes Grail byte views as libsodium's
(pointer, length) pairs. Nothing cryptographic is reimplemented.

Covered: ChaCha20-Poly1305 and XChaCha20-Poly1305 IETF AEAD (sealed = ciphertext || tag),
BLAKE2b (keyed or not, 16-64 byte output), SHA-256, SipHash-2-4, Poly1305, X25519 (base point and
shared secret), the ChaCha20 IETF stream, HChaCha20 and `randombytes_buf`.

## Use

`grail.pkg`:

```
dep sodium https://github.com/sashaduke/grail-sodium
```

```grail
use sodium;

fn main() {
    if sodium::init() == false {
        return;
    }
    key := sodium::random_bytes(32);
    nonce := sodium::random_bytes(24);
    sealed := sodium::xchacha20poly1305_ietf_encrypt("hello", "header", &nonce, &key)!;
    opened := sodium::xchacha20poly1305_ietf_decrypt(&sealed, "header", &nonce, &key)!;
    println(opened.len());
}
```

Wrong key or nonce lengths, and authentication failures, return `None`.

Requires libsodium (1.0.18 or later) where the program runs and links (`-lsodium`), and a Grail
compiler with bare FFI pointers (`CPtr`/`CMutPtr`) and `grail build` foreign-library linking.

## Tests

`grail test` checks every primitive against libsodium on the RFC 8439 (AEAD, Poly1305) and
RFC 7748 (X25519) inputs and the SipHash reference vector, plus round trips and tag tampering.
`tests/reference/ref.c` regenerates the expected values.

## License

MIT (`LICENSE`). libsodium itself is ISC-licensed and is not included.
