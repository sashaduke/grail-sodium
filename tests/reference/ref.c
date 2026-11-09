#include <sodium.h>
#include <stdio.h>
#include <string.h>
static void hex(const char *name, const unsigned char *p, size_t n) { printf("%s ", name); for (size_t i = 0; i < n; i++) printf("%02x", p[i]); printf("\n"); }
int main(void) {
    if (sodium_init() < 0) return 1;
    const char *pt = "Ladies and Gentlemen of the class of '99: If I could offer you only one tip for the future, sunscreen would be it.";
    size_t n = strlen(pt);
    unsigned char ad[12] = {0x50,0x51,0x52,0x53,0xc0,0xc1,0xc2,0xc3,0xc4,0xc5,0xc6,0xc7};
    unsigned char key[32]; for (int i = 0; i < 32; i++) key[i] = 0x80 + i;
    unsigned char nonce[12] = {0x07,0,0,0,0x40,0x41,0x42,0x43,0x44,0x45,0x46,0x47};
    unsigned char xnonce[24]; for (int i = 0; i < 24; i++) xnonce[i] = 0x40 + i;
    unsigned char c[200], mac[16];
    crypto_aead_chacha20poly1305_ietf_encrypt_detached(c, mac, NULL, (const unsigned char *)pt, n, ad, 12, NULL, nonce, key);
    memcpy(c + n, mac, 16); hex("aead", c, n + 16);
    crypto_aead_xchacha20poly1305_ietf_encrypt_detached(c, mac, NULL, (const unsigned char *)pt, n, ad, 12, NULL, xnonce, key);
    memcpy(c + n, mac, 16); hex("xaead", c, n + 16);
    unsigned char h[64]; crypto_generichash_blake2b(h, 64, (const unsigned char *)"abc", 3, NULL, 0); hex("b2b", h, 64);
    crypto_generichash_blake2b(h, 32, (const unsigned char *)"abc", 3, key, 32); hex("b2bk", h, 32);
    crypto_hash_sha256(h, (const unsigned char *)"abc", 3); hex("sha", h, 32);
    unsigned char sk[16], m[15], sh[8]; for (int i = 0; i < 16; i++) sk[i] = i; for (int i = 0; i < 15; i++) m[i] = i;
    crypto_shorthash_siphash24(sh, m, 15, sk); hex("sip", sh, 8);
    crypto_onetimeauth_poly1305(h, (const unsigned char *)"Cryptographic Forum Research Group", 34, key); hex("poly", h, 16);
    unsigned char a[32] = {0x77,0x07,0x6d,0x0a,0x73,0x18,0xa5,0x7d,0x3c,0x16,0xc1,0x72,0x51,0xb2,0x66,0x45,0xdf,0x4c,0x2f,0x87,0xeb,0xc0,0x99,0x2a,0xb1,0x77,0xfb,0xa5,0x1d,0xb9,0x2c,0x2a};
    unsigned char b[32] = {0x5d,0xab,0x08,0x7e,0x62,0x4a,0x8a,0x4b,0x79,0xe1,0x7f,0x8b,0x83,0x80,0x0e,0xe6,0x6f,0x3b,0xb1,0x29,0x26,0x18,0xb6,0xfd,0x1c,0x2f,0x8b,0x27,0xff,0x88,0xe0,0xeb};
    unsigned char pa[32], pb[32], s[32];
    crypto_scalarmult_curve25519_base(pa, a); hex("xpub", pa, 32);
    crypto_scalarmult_curve25519_base(pb, b);
    crypto_scalarmult_curve25519(s, a, pb); hex("xshared", s, 32);
    crypto_stream_chacha20_ietf_xor_ic(c, (const unsigned char *)pt, n, nonce, 1, key); hex("stream", c, n);
    unsigned char in16[16]; for (int i = 0; i < 16; i++) in16[i] = i;
    crypto_core_hchacha20(h, in16, key, NULL); hex("hchacha", h, 32);
    return 0;
}
