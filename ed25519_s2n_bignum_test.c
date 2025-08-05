#include <stdio.h>
#include "ed25519_s2n_bignum.h"

#define MAX_MSG_LEN 48

void hex_to_bytes(const char *hex, uint8_t *bytes, size_t len) {
    for(int i = 0; i < len; i++) {
        sscanf(&hex[i * 2], "%2hhx", &bytes[i]);
    }
}

void print_bytes(const uint8_t *bytes, size_t len) {
    for (int i = 0; i < len; i++) {
        printf("%02x", bytes[i]);
    }
    printf("\n");
}

int compare_bytes(const uint8_t *a, const uint8_t *b, size_t len) {
    for (int i = 0; i < len; i++) {
        if (a[i] != b[i]) return a[i] - b[i];
    }
    return 0;
}

void ed25519_test(const char *seed_str, const char *pub_key_str, const char *msg_str, size_t msg_len, const char *sig_str) {
    uint8_t seed[32];
    hex_to_bytes(seed_str, seed, 32);
    printf("seed:\n");
    print_bytes(seed, 32);

    printf("l = %ld\n", msg_len);
    uint8_t pub_key[32];
    ed25519_keypair_from_seed_s2n_bignum(pub_key, seed);
    printf("l = %ld\n", msg_len);
    printf("public key:\n");
    print_bytes(pub_key, 32);

    uint8_t priv_key[64];
    for(int i = 0; i < 32; i++) {
        priv_key[i] = seed[i];
        priv_key[32+i] = pub_key[i];
    }
    printf("private key:\n");
    print_bytes(priv_key, 64);

    uint8_t sig[64];
    uint8_t msg[MAX_MSG_LEN];
    hex_to_bytes(msg_str, msg, msg_len);
    printf("cp1");
    ed25519_sign_no_self_test_s2n_bignum(sig, msg, msg_len, priv_key);
    printf("signature:\n");
    print_bytes(sig, 64);

    printf("verification result:\n");
    printf("%d\n", ed25519_verify_no_self_test_s2n_bignum(msg, msg_len, sig, pub_key));

    uint8_t pub_key_expected[32];
    hex_to_bytes(pub_key_str, pub_key_expected, 32);
    uint8_t sig_expected[64];
    hex_to_bytes(sig_str, sig_expected, 64);

    if (compare_bytes(pub_key, pub_key_expected, 32) != 0) {
        printf("Public key different from expected:\n");
        print_bytes(pub_key_expected, 32);
    } else {
        printf("Public key same as expected\n");
    }

    if (compare_bytes(sig, sig_expected, 64) != 0) {
        printf("Signature different from expected:\n");
        print_bytes(sig_expected, 64);
    } else {
        printf("Signature same as expected\n");
    }
}

int main (){
    const char seed_str[64] = "9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60";
    const char pub_key_str[64] = "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a";
    const char sig_str[128] = "e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e065224901555fb8821590a33bacc61e39701cf9b46bd25bf5f0595bbe24655141438e7a100b";
    ed25519_test(seed_str, pub_key_str, NULL, 0, sig_str);
    return 0;
    // uint8_t seed[32] = {0x9d, 0x61, 0xb1, 0x9d, 0xef, 0xfd, 0x5a, 0x60, 0xba, 0x84, 0x4a, 0xf4, 0x92, 0xec, 0x2c, 0xc4,
    //     0x44, 0x49, 0xc5, 0x69, 0x7b, 0x32, 0x69, 0x19, 0x70, 0x3b, 0xac, 0x03, 0x1c, 0xae, 0x7f, 0x60};

    // uint8_t seed[32] = {0x4c, 0xcd, 0x08, 0x9b, 0x28, 0xff, 0x96, 0xda, 0x9d, 0xb6, 0xc3, 0x46, 0xec, 0x11, 0x4e, 0x0f,
    //     0x5b, 0x8a, 0x31, 0x9f, 0x35, 0xab, 0xa6, 0x24, 0xda, 0x8c, 0xf6, 0xed, 0x4f, 0xb8, 0xa6, 0xfb};

    // // Ed25519ctx
    // uint8_t seed[32] = {0x03, 0x05, 0x33, 0x4e, 0x38, 0x1a, 0xf7, 0x8f, 0x14, 0x1c, 0xb6, 0x66, 0xf6, 0x19, 0x9f, 0x57,
    //     0xbc, 0x34, 0x95, 0x33, 0x5a, 0x25, 0x6a, 0x95, 0xbd, 0x2a, 0x55, 0xbf, 0x54, 0x66, 0x63, 0xf6};

    // Ed25519ph
    uint8_t seed[32] = {0x83, 0x3f, 0xe6, 0x24, 0x09, 0x23, 0x7b, 0x9d, 0x62, 0xec, 0x77, 0x58, 0x75, 0x20, 0x91, 0x1e,
        0x9a, 0x75, 0x9c, 0xec, 0x1d, 0x19, 0x75, 0x5b, 0x7d, 0xa9, 0x01, 0xb9, 0x6d, 0xca, 0x3d, 0x42};

    uint8_t pub_key[32];
    ed25519_keypair_from_seed_s2n_bignum (pub_key, seed);

    printf("seed\n");
    for(int i = 0; i < 32; i++) {
        printf("%02x", seed[i]);
    }
    printf("\n");
    printf("\n");
    printf("public key\n");
    for(int i = 0; i < 32; i++) {
        printf("%02x", pub_key[i]);
    }
    printf("\n");
    printf("\n");

    uint8_t priv_key [64];
    for(int i = 0; i < 32; i++) {
        priv_key[i] = seed[i];
        priv_key[32+i] = pub_key[i];
    }
    printf("private key\n");
    for(int i = 0; i < 64; i++) {
        printf("%02x", priv_key[i]);
    }
    printf("\n");
    printf("\n");

    uint8_t sig[64];

    // uint8_t msg[16];
    // ed25519_sign_no_self_test_s2n_bignum(sig, msg, 0, priv_key);

    // uint8_t msg[16];
    // msg[0] = 0x72;
    // ed25519_sign_no_self_test_s2n_bignum(sig, msg, 1, priv_key);

    // uint8_t msg[16] = {0xf7, 0x26, 0x93, 0x6d, 0x19, 0xc8, 0x00, 0x49, 0x4e, 0x3f, 0xda, 0xff, 0x20, 0xb2, 0x76, 0xa8};
    // uint8_t ctx[3] = {0x66, 0x6f, 0x6f};
    // ed25519ctx_sign_no_self_test_s2n_bignum(sig, msg, 16, priv_key, ctx, 3);

    uint8_t msg[3] = {0x61, 0x62, 0x63};
    ed25519ph_sign_no_self_test_s2n_bignum(sig, msg, 3, priv_key, NULL, 0);

    printf("signature\n");
    for(int i = 0; i < 64; i++) {
        printf("%02x", sig[i]);
    }
    printf("\n");
    printf("\n");

    printf("verification\n");
    // printf("%d\n", ed25519_verify_no_self_test_s2n_bignum(msg, 0, sig, pub_key));
    // printf("%d\n", ed25519_verify_no_self_test_s2n_bignum(msg, 1, sig, pub_key));
    
    // printf("%d\n", ed25519ctx_verify_no_self_test_s2n_bignum(msg, 16, sig, pub_key, ctx, 3));

    printf("%d\n", ed25519ph_verify_no_self_test_s2n_bignum(msg, 3, sig, pub_key, NULL, 0));

    return 0;
}