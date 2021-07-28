#include <stdio.h>

#include "ecdsa.h"
#include "secp256k1.h"

// Expected result is: f68df2227e39c9ba87baea5966f0c52b03831b10a39e96a721cd2770362d54bae75dcf35a18c17a3a8cf76bfa91a0a41969c0a163ba6d2e6aa1a851
void test_sign_secp256k1(void) {

    uint8_t out[64], priv[32], pby;

    uint8_t digest[] = { 0xbc, 0x4c, 0x91, 0x5d, 0x69, 0x89, 0x6b, 0x19,
                         0x8f, 0x02, 0x92, 0xa7, 0x23, 0x73, 0xa2, 0xbd,
                         0xcd, 0x0d, 0x52, 0xbc, 0xcb, 0xfc, 0xec, 0x11,
                         0xd9, 0xc8, 0x4c, 0x0f, 0xff, 0x71, 0xb0, 0xbc
    };

    const ecdsa_curve *curve = &secp256k1;

    memcpy(priv,
           "\xa0\x37\x9a\xf1\x9f\x0b\x55\xb0\xf3\x84\xf8\x3c\x95\xf6\x68\xba\x60"
           "\x0b\x78\xf4\x87\xf6\x41\x4f\x2d\x22\x33\x92\x73\x89\x1e\xec",
           32);

    ecdsa_sign_digest(curve, priv, digest, out, &pby, NULL);

    for(int i=0; i<64; i++) {
        printf("%x", out[i]);
    }
    printf("%x\n", pby);
}

int main(void) {

    test_sign_secp256k1();
}
