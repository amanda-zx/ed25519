#include <stdio.h>
#include "ed25519_s2n_bignum.h"

#include <string.h>

#define MAX_MSG_LEN 4096

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
    printf("\n");

    uint8_t pub_key[32];
    ed25519_keypair_from_seed_s2n_bignum(pub_key, seed);
    printf("public key:\n");
    print_bytes(pub_key, 32);
    printf("\n");

    uint8_t priv_key[64];
    for(int i = 0; i < 32; i++) {
        priv_key[i] = seed[i];
        priv_key[32+i] = pub_key[i];
    }
    printf("private key:\n");
    print_bytes(priv_key, 64);
    printf("\n");

    uint8_t sig[64];
    uint8_t msg[MAX_MSG_LEN];
    hex_to_bytes(msg_str, msg, msg_len);
    ed25519_sign_no_self_test_s2n_bignum(sig, msg, msg_len, priv_key);
    printf("signature:\n");
    print_bytes(sig, 64);
    printf("\n");

    printf("verification (1 for success):\n");
    printf("%d\n", ed25519_verify_no_self_test_s2n_bignum(msg, msg_len, sig, pub_key));
    printf("\n");

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

void ed25519_test_1() {
    printf("-----TEST 1\n");
    const char *seed_str = "9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60";
    const char *pub_key_str = "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a";
    const char *sig_str = "e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e065224901555fb8821590a33bacc61e39701cf9b46bd25bf5f0595bbe24655141438e7a100b";
    ed25519_test(seed_str, pub_key_str, NULL, 0, sig_str);
    printf("-----\n");
}

void ed25519_test_2() {
    printf("-----TEST 2\n");
    const char *seed_str = "4ccd089b28ff96da9db6c346ec114e0f5b8a319f35aba624da8cf6ed4fb8a6fb";
    const char *pub_key_str = "3d4017c3e843895a92b70aa74d1b7ebc9c982ccf2ec4968cc0cd55f12af4660c";
    const char *msg_str = "72";
    size_t msg_len = 1;
    const char *sig_str = "92a009a9f0d4cab8720e820b5f642540a2b27b5416503f8fb3762223ebdb69da085ac1e43e15996e458f3613d0f11d8c387b2eaeb4302aeeb00d291612bb0c00";
    ed25519_test(seed_str, pub_key_str, msg_str, msg_len, sig_str);
    printf("-----\n");
}

void ed25519_test_3() {
    printf("-----TEST 3\n");
    const char *seed_str = "c5aa8df43f9f837bedb7442f31dcb7b166d38535076f094b85ce3a2e0b4458f7";
    const char *pub_key_str = "fc51cd8e6218a1a38da47ed00230f0580816ed13ba3303ac5deb911548908025";
    const char *msg_str = "af82";
    size_t msg_len = 2;
    const char *sig_str = "6291d657deec24024827e69c3abe01a30ce548a284743a445e3680d7db5ac3ac18ff9b538d16f290ae67f760984dc6594a7c15e9716ed28dc027beceea1ec40a";
    ed25519_test(seed_str, pub_key_str, msg_str, msg_len, sig_str);
    printf("-----\n");
}

void ed25519_test_1024() {
    printf("-----TEST 1024\n");
    const char *seed_str = "f5e5767cf153319517630f226876b86c8160cc583bc013744c6bf255f5cc0ee5";
    const char *pub_key_str = "278117fc144c72340f67d0f2316e8386ceffbf2b2428c9c51fef7c597f1d426e";
    const char msg_str[2048] = "08b8b2b733424243760fe426a4b54908632110a66c2f6591eabd3345e3e4eb98"
        "fa6e264bf09efe12ee50f8f54e9f77b1e355f6c50544e23fb1433ddf73be84d8"
        "79de7c0046dc4996d9e773f4bc9efe5738829adb26c81b37c93a1b270b20329d"
        "658675fc6ea534e0810a4432826bf58c941efb65d57a338bbd2e26640f89ffbc"
        "1a858efcb8550ee3a5e1998bd177e93a7363c344fe6b199ee5d02e82d522c4fe"
        "ba15452f80288a821a579116ec6dad2b3b310da903401aa62100ab5d1a36553e"
        "06203b33890cc9b832f79ef80560ccb9a39ce767967ed628c6ad573cb116dbef"
        "efd75499da96bd68a8a97b928a8bbc103b6621fcde2beca1231d206be6cd9ec7"
        "aff6f6c94fcd7204ed3455c68c83f4a41da4af2b74ef5c53f1d8ac70bdcb7ed1"
        "85ce81bd84359d44254d95629e9855a94a7c1958d1f8ada5d0532ed8a5aa3fb2"
        "d17ba70eb6248e594e1a2297acbbb39d502f1a8c6eb6f1ce22b3de1a1f40cc24"
        "554119a831a9aad6079cad88425de6bde1a9187ebb6092cf67bf2b13fd65f270"
        "88d78b7e883c8759d2c4f5c65adb7553878ad575f9fad878e80a0c9ba63bcbcc"
        "2732e69485bbc9c90bfbd62481d9089beccf80cfe2df16a2cf65bd92dd597b07"
        "07e0917af48bbb75fed413d238f5555a7a569d80c3414a8d0859dc65a46128ba"
        "b27af87a71314f318c782b23ebfe808b82b0ce26401d2e22f04d83d1255dc51a"
        "ddd3b75a2b1ae0784504df543af8969be3ea7082ff7fc9888c144da2af58429e"
        "c96031dbcad3dad9af0dcbaaaf268cb8fcffead94f3c7ca495e056a9b47acdb7"
        "51fb73e666c6c655ade8297297d07ad1ba5e43f1bca32301651339e22904cc8c"
        "42f58c30c04aafdb038dda0847dd988dcda6f3bfd15c4b4c4525004aa06eeff8"
        "ca61783aacec57fb3d1f92b0fe2fd1a85f6724517b65e614ad6808d6f6ee34df"
        "f7310fdc82aebfd904b01e1dc54b2927094b2db68d6f903b68401adebf5a7e08"
        "d78ff4ef5d63653a65040cf9bfd4aca7984a74d37145986780fc0b16ac451649"
        "de6188a7dbdf191f64b5fc5e2ab47b57f7f7276cd419c17a3ca8e1b939ae49e4"
        "88acba6b965610b5480109c8b17b80e1b7b750dfc7598d5d5011fd2dcc5600a3"
        "2ef5b52a1ecc820e308aa342721aac0943bf6686b64b2579376504ccc493d97e"
        "6aed3fb0f9cd71a43dd497f01f17c0e2cb3797aa2a2f256656168e6c496afc5f"
        "b93246f6b1116398a346f1a641f3b041e989f7914f90cc2c7fff357876e506b5"
        "0d334ba77c225bc307ba537152f3f1610e4eafe595f6d9d90d11faa933a15ef1"
        "369546868a7f3a45a96768d40fd9d03412c091c6315cf4fde7cb68606937380d"
        "b2eaaa707b4c4185c32eddcdd306705e4dc1ffc872eeee475a64dfac86aba41c"
        "0618983f8741c5ef68d3a101e8a3b8cac60c905c15fc910840b94c00a0b9d0";
    size_t msg_len = 1023;
    const char *sig_str = "0aab4c900501b3e24d7cdf4663326a3a87df5e4843b2cbdb67cbf6e460fec350aa5371b1508f9f4528ecea23c436d94b5e8fcd4f681e30a6ac00a9704a188a03";
    ed25519_test(seed_str, pub_key_str, msg_str, msg_len, sig_str);
    printf("-----\n");
}

void ed25519_test_sha_abc() {
    printf("-----TEST SHA(abc)\n");
    const char *seed_str = "833fe62409237b9d62ec77587520911e9a759cec1d19755b7da901b96dca3d42";
    const char *pub_key_str = "ec172b93ad5e563bf4932c70e1245034c35467ef2efd4d64ebf819683467e2bf";
    const char *msg_str = "ddaf35a193617abacc417349ae204131"
        "12e6fa4e89a97ea20a9eeee64b55d39a"
        "2192992a274fc1a836ba3c23a3feebbd"
        "454d4423643ce80e2a9ac94fa54ca49f";
    size_t msg_len = 64;
    const char *sig_str = "dc2a4459e7369633a52b1bf277839a00201009a3efbf3ecb69bea2186c26b58909351fc9ac90b3ecfdfbc7c66431e0303dca179c138ac17ad9bef1177331a704";
    ed25519_test(seed_str, pub_key_str, msg_str, msg_len, sig_str);
    printf("-----\n");
} 

void ed25519ctx_test(const char *seed_str, const char *pub_key_str, const char *msg_str, size_t msg_len,
        const char *ctx_str, size_t ctx_len, const char *sig_str) {
    uint8_t seed[32];
    hex_to_bytes(seed_str, seed, 32);
    printf("seed:\n");
    print_bytes(seed, 32);
    printf("\n");

    uint8_t pub_key[32];
    ed25519_keypair_from_seed_s2n_bignum(pub_key, seed);
    printf("public key:\n");
    print_bytes(pub_key, 32);
    printf("\n");

    uint8_t priv_key[64];
    for(int i = 0; i < 32; i++) {
        priv_key[i] = seed[i];
        priv_key[32+i] = pub_key[i];
    }
    printf("private key:\n");
    print_bytes(priv_key, 64);
    printf("\n");

    uint8_t ctx[512];
    hex_to_bytes(ctx_str, ctx, ctx_len);

    uint8_t sig[64];
    uint8_t msg[MAX_MSG_LEN];
    hex_to_bytes(msg_str, msg, msg_len);
    ed25519ctx_sign_no_self_test_s2n_bignum(sig, msg, msg_len, priv_key, ctx, ctx_len);
    printf("signature:\n");
    print_bytes(sig, 64);
    printf("\n");

    printf("verification (1 for success):\n");
    printf("%d\n", ed25519ctx_verify_no_self_test_s2n_bignum(msg, msg_len, sig, pub_key, ctx, ctx_len));
    printf("\n");

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

void ed25519ctx_foo() {
    printf("-----foo\n");
    const char *seed_str = "0305334e381af78f141cb666f6199f57bc3495335a256a95bd2a55bf546663f6";
    const char *pub_key_str = "dfc9425e4f968f7f0c29f0259cf5f9aed6851c2bb4ad8bfb860cfee0ab248292";
    const char *msg_str = "f726936d19c800494e3fdaff20b276a8";
    size_t msg_len = 16;
    const char *ctx_str = "666f6f";
    size_t ctx_len = 3;
    const char *sig_str = "55a4cc2f70a54e04288c5f4cd1e45a7bb520b36292911876cada7323198dd87a8b36950b95130022907a7fb7c4e9b2d5f6cca685a587b4b21f4b888e4e7edb0d";
    ed25519ctx_test(seed_str, pub_key_str, msg_str, msg_len, ctx_str, ctx_len, sig_str);
    printf("-----\n");
}

void ed25519ctx_bar() {
    printf("-----bar\n");
    const char *seed_str = "0305334e381af78f141cb666f6199f57bc3495335a256a95bd2a55bf546663f6";
    const char *pub_key_str = "dfc9425e4f968f7f0c29f0259cf5f9aed6851c2bb4ad8bfb860cfee0ab248292";
    const char *msg_str = "f726936d19c800494e3fdaff20b276a8";
    size_t msg_len = 16;
    const char *ctx_str = "626172";
    size_t ctx_len = 3;
    const char *sig_str = "fc60d5872fc46b3aa69f8b5b4351d5808f92bcc044606db097abab6dbcb1aee3216c48e8b3b66431b5b186d1d28f8ee15a5ca2df6668346291c2043d4eb3e90d";
    ed25519ctx_test(seed_str, pub_key_str, msg_str, msg_len, ctx_str, ctx_len, sig_str);
    printf("-----\n");
}

void ed25519ctx_foo2() {
    printf("-----foo2\n");
    const char *seed_str = "0305334e381af78f141cb666f6199f57bc3495335a256a95bd2a55bf546663f6";
    const char *pub_key_str = "dfc9425e4f968f7f0c29f0259cf5f9aed6851c2bb4ad8bfb860cfee0ab248292";
    const char *msg_str = "508e9e6882b979fea900f62adceaca35";
    size_t msg_len = 16;
    const char *ctx_str = "666f6f";
    size_t ctx_len = 3;
    const char *sig_str = "8b70c1cc8310e1de20ac53ce28ae6e7207f33c3295e03bb5c0732a1d20dc64908922a8b052cf99b7c4fe107a5abb5b2c4085ae75890d02df26269d8945f84b0b";
    ed25519ctx_test(seed_str, pub_key_str, msg_str, msg_len, ctx_str, ctx_len, sig_str);
    printf("-----\n");
}

void ed25519ctx_foo3() {
    printf("-----foo3\n");
    const char *seed_str = "ab9c2853ce297ddab85c993b3ae14bcad39b2c682beabc27d6d4eb20711d6560";
    const char *pub_key_str = "0f1d1274943b91415889152e893d80e93275a1fc0b65fd71b4b0dda10ad7d772";
    const char *msg_str = "f726936d19c800494e3fdaff20b276a8";
    size_t msg_len = 16;
    const char *ctx_str = "666f6f";
    size_t ctx_len = 3;
    const char *sig_str = "21655b5f1aa965996b3f97b3c849eafba922a0a62992f73b3d1b73106a84ad85e9b86a7b6005ea868337ff2d20a7f5fbd4cd10b0be49a68da2b2e0dc0ad8960f";
    ed25519ctx_test(seed_str, pub_key_str, msg_str, msg_len, ctx_str, ctx_len, sig_str);
    printf("-----\n");
}

void ed25519ph_test(const char *seed_str, const char *pub_key_str, const char *msg_str, size_t msg_len,
        const char *ctx_str, size_t ctx_len, const char *sig_str) {
    uint8_t seed[32];
    hex_to_bytes(seed_str, seed, 32);
    printf("seed:\n");
    print_bytes(seed, 32);
    printf("\n");

    uint8_t pub_key[32];
    ed25519_keypair_from_seed_s2n_bignum(pub_key, seed);
    printf("public key:\n");
    print_bytes(pub_key, 32);
    printf("\n");

    uint8_t priv_key[64];
    for(int i = 0; i < 32; i++) {
        priv_key[i] = seed[i];
        priv_key[32+i] = pub_key[i];
    }
    printf("private key:\n");
    print_bytes(priv_key, 64);
    printf("\n");

    uint8_t ctx[512];
    hex_to_bytes(ctx_str, ctx, ctx_len);

    uint8_t sig[64];
    uint8_t msg[MAX_MSG_LEN];
    hex_to_bytes(msg_str, msg, msg_len);
    ed25519ph_sign_no_self_test_s2n_bignum(sig, msg, msg_len, priv_key, ctx, ctx_len);
    printf("signature:\n");
    print_bytes(sig, 64);
    printf("\n");

    printf("verification (1 for success):\n");
    printf("%d\n", ed25519ph_verify_no_self_test_s2n_bignum(msg, msg_len, sig, pub_key, ctx, ctx_len));
    printf("\n");

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

void ed25519ph_test_abc() {
    printf("-----TEST abc\n");
    const char *seed_str = "833fe62409237b9d62ec77587520911e9a759cec1d19755b7da901b96dca3d42";
    const char *pub_key_str = "ec172b93ad5e563bf4932c70e1245034c35467ef2efd4d64ebf819683467e2bf";
    const char *msg_str = "616263";
    size_t msg_len = 3;
    const char *sig_str = "98a70222f0b8121aa9d30f813d683f809e462b469c7ff87639499bb94e6dae4131f85042463c2a355a2003d062adf5aaa10b8c61e636062aaad11c2a26083406";
    ed25519ph_test(seed_str, pub_key_str, msg_str, msg_len, NULL, 0, sig_str);
    printf("-----\n");
}

int main (){
    printf("=====Testing Ed25519=====\n");
    ed25519_test_1();
    ed25519_test_2();
    ed25519_test_3();
    ed25519_test_1024();
    ed25519_test_sha_abc();
    printf("=====Testing Ed25519ctx=====\n");
    ed25519ctx_foo();
    ed25519ctx_bar();
    ed25519ctx_foo2();
    ed25519ctx_foo3();
    printf("=====Testing Ed25519ph=====\n");
    ed25519ph_test_abc();

    // uint8_t seed[32] = {0x9d, 0x61, 0xb1, 0x9d, 0xef, 0xfd, 0x5a, 0x60, 0xba, 0x84, 0x4a, 0xf4, 0x92, 0xec, 0x2c, 0xc4,
    //     0x44, 0x49, 0xc5, 0x69, 0x7b, 0x32, 0x69, 0x19, 0x70, 0x3b, 0xac, 0x03, 0x1c, 0xae, 0x7f, 0x60};

    // // uint8_t seed[32] = {0x4c, 0xcd, 0x08, 0x9b, 0x28, 0xff, 0x96, 0xda, 0x9d, 0xb6, 0xc3, 0x46, 0xec, 0x11, 0x4e, 0x0f,
    // //     0x5b, 0x8a, 0x31, 0x9f, 0x35, 0xab, 0xa6, 0x24, 0xda, 0x8c, 0xf6, 0xed, 0x4f, 0xb8, 0xa6, 0xfb};

    // // // Ed25519ctx
    // // uint8_t seed[32] = {0x03, 0x05, 0x33, 0x4e, 0x38, 0x1a, 0xf7, 0x8f, 0x14, 0x1c, 0xb6, 0x66, 0xf6, 0x19, 0x9f, 0x57,
    // //     0xbc, 0x34, 0x95, 0x33, 0x5a, 0x25, 0x6a, 0x95, 0xbd, 0x2a, 0x55, 0xbf, 0x54, 0x66, 0x63, 0xf6};

    // // // Ed25519ph
    // // uint8_t seed[32] = {0x83, 0x3f, 0xe6, 0x24, 0x09, 0x23, 0x7b, 0x9d, 0x62, 0xec, 0x77, 0x58, 0x75, 0x20, 0x91, 0x1e,
    // //     0x9a, 0x75, 0x9c, 0xec, 0x1d, 0x19, 0x75, 0x5b, 0x7d, 0xa9, 0x01, 0xb9, 0x6d, 0xca, 0x3d, 0x42};

    // uint8_t pub_key[32];
    // ed25519_keypair_from_seed_s2n_bignum (pub_key, seed);

    // printf("seed\n");
    // for(int i = 0; i < 32; i++) {
    //     printf("%02x", seed[i]);
    // }
    // printf("\n");
    // printf("\n");
    // printf("public key\n");
    // for(int i = 0; i < 32; i++) {
    //     printf("%02x", pub_key[i]);
    // }
    // printf("\n");
    // printf("\n");

    // uint8_t priv_key [64];
    // for(int i = 0; i < 32; i++) {
    //     priv_key[i] = seed[i];
    //     priv_key[32+i] = pub_key[i];
    // }
    // printf("private key\n");
    // print_bytes(priv_key, 64);
    // printf("\n");

    // uint8_t sig[64];

    // uint8_t msg[16];
    // ed25519_sign_no_self_test_s2n_bignum(sig, msg, 0, priv_key);

    // // uint8_t msg[16];
    // // msg[0] = 0x72;
    // // ed25519_sign_no_self_test_s2n_bignum(sig, msg, 1, priv_key);

    // // uint8_t msg[16] = {0xf7, 0x26, 0x93, 0x6d, 0x19, 0xc8, 0x00, 0x49, 0x4e, 0x3f, 0xda, 0xff, 0x20, 0xb2, 0x76, 0xa8};
    // // uint8_t ctx[3] = {0x66, 0x6f, 0x6f};
    // // ed25519ctx_sign_no_self_test_s2n_bignum(sig, msg, 16, priv_key, ctx, 3);

    // // uint8_t msg[3] = {0x61, 0x62, 0x63};
    // // ed25519ph_sign_no_self_test_s2n_bignum(sig, msg, 3, priv_key, NULL, 0);

    // printf("signature\n");
    // print_bytes(sig, 64);
    // printf("\n");

    // printf("verification\n");
    // printf("%d\n", ed25519_verify_no_self_test_s2n_bignum(msg, 0, sig, pub_key));
    // // printf("%d\n", ed25519_verify_no_self_test_s2n_bignum(msg, 1, sig, pub_key));
    
    // // printf("%d\n", ed25519ctx_verify_no_self_test_s2n_bignum(msg, 16, sig, pub_key, ctx, 3));

    // // printf("%d\n", ed25519ph_verify_no_self_test_s2n_bignum(msg, 3, sig, pub_key, NULL, 0));

    // return 0;
}