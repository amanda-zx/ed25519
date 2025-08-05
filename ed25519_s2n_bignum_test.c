#include <stdio.h>
#include "ed25519_s2n_bignum.h"

int main (){
    uint8_t seed[32] = {0};
    uint8_t pub_key[32];
    ed25519_keypair_from_seed_s2n_bignum (pub_key, seed);
    for(int i = 0; i < 32; i++) {
        printf("%02x", pub_key[i]);
    }

    return 0;
}