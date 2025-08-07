gcc -c ed25519.S

For testing,
gcc -o test ed25519.S ed25519_s2n_bignum_test.c
./test