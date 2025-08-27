# Ed25519 final integration plan

This document uses pseudocode to describe the implementation of Ed25519 subroutines, how the top-level routines should be integrated into AWS-LC, and the specifications of the top-level routines.

```
#define ED25519_PUBLIC_KEY_LEN 32
#define ED25519_SEED_LEN 32
#define SHA512_DIGEST_LEN 64
#define ED25519_SIGNATURE_LEN 64
#define ED25519_PRIVATE_KEY_LEN 64
#define MAX_DOM2_SIZE 289
```

## Pseudocode implementation

### Key generation

```
void ed25519_public_key_from_seed_s2n_bignum (
  uint8_t A[ED25519_PUBLIC_KEY_LEN],
  const uint8_t seed[ED25519_SEED_LEN]){
  // Ed25519 key generation: rfc8032 5.1.5
  
  // Step: rfc8032 5.1.5.1
  // Compute SHA512(seed).
  // Through sha512_init, sha512_update, sha512_final
  uint8_t h[SHA512_DIGEST_LEN];
  h[0:63] = sha512_s2n_bignum(seed[0:31]);

  // Step: rfc8032 5.1.5.2
  // Clamp h[0:31]
  h[0] &= 248; // 11111000_2
  h[31] &= 127; // 01111111_2
  h[31] |= 64; // 01000000_2

  // Step: rfc8032 5.1.5.3
  // Compute [s]B and encode public key to a 32 byte octet
  //   where s = h[0:31]
  uint64_t s_B[8] = {0};
  edwards25519_scalarmulbase_selector(s_B, h);
  
  // Step: rfc8032 5.1.5.4
  edwards25519_encode(A, s_B);
}
```

### Common subroutines

```
void ed25519_sign_common(
    uint8_t out_sig[ED25519_SIGNATURE_LEN], const uint8_t *message,
    size_t message_len, const uint8_t private_key[ED25519_PRIVATE_KEY_LEN],
    uint8_t *dom2_buffer, size_t dom2_buffer_len) {
  // Ed25519 sign: rfc8032 5.1.6

  // Step: rfc8032 5.1.6.1
  // This step is a repeat of rfc8032 5.1.5.[1,2].
  // seed = private_key[0:31]
  // Compute h = SHA512(seed).
  // Through sha512_init, sha512_update, sha512_final
  uint8_t h[SHA512_DIGEST_LEN];
  h[0:63] = sha512_s2n_bignum(private_key[0:31]);
  // Clamp h[0:31]
  h[0] &= 248; // 11111000_2
  h[31] &= 63; // 00111111_2
  h[31] |= 64; // 01000000_2
  
  // Step: rfc8032 5.1.6.2
  // prefix = h[32:63]
  uint8_t r[SHA512_DIGEST_LEN];
  r[0:63] = sha512_s2n_bignum(dom2_buffer || h[32:63] || message);

  // Step: rfc8032 5.1.6.3
  uint64_t r_B[8];

  // Reduce r modulo the order of the base-point B.
  bignum_mod_n25519(r, 8, r);

  // Compute [r]B.
  edwards25519_scalarmulbase_selector(r_B, r);
  edwards25519_encode(out_sig, r_B);
  
  // Step: rfc8032 5.1.6.4
  // R = out_sig[0:31]
  // A = private_key[32:63]
  uint8_t k[SHA512_DIGEST_LEN];
  k[0:63] = sha512_s2n_bignum(dom2_buffer || out_sig[0:31] || private_key[32:63] || message);
  
  // Step: rfc8032 5.1.6.5
  // Compute S = r + k * s modulo the order of the base-point B
  //   where s = h[0:31]
  // Step: rfc8032 5.1.6.6
  // out_sig = R || S
  bignum_mod_n25519(k, 8, k);
  bignum_madd_n25519_selector(out_sig + 32, k, s, r);
}
```

```
int ed25519_verify_common(
    const uint8_t *message, size_t message_len,
    const uint8_t signature[ED25519_SIGNATURE_LEN],
    const uint8_t public_key[ED25519_PUBLIC_KEY_LEN],
    const uint8_t *dom2_buffer, size_t dom2_buffer_len) {
  // Ed25519 verify: rfc8032 5.1.7
  
  // Step: rfc8032 5.1.7.1
  // Decode signature as:
  //  - signature[0:31]: encoded point R.
  //  - signature[32:63]: integer S.

  // S must be in the range [0, ORDER) in order to prevent signature
  // malleability. ORDER is the order of curve25519 in little-endian form.
  uint8_t order[32] = ORDER;
  if (bignum_le(32, order, 32, signature + 32)) return 0;
  
  // Decode public key as A.
  uint64_t A[8];
  if (edwards25519_decode_selector(A, public_key) != 0) {
    return 0;
  }

  // Step: rfc8032 5.1.7.2
  uint8_t k[SHA512_DIGEST_LEN];
  k[0:63] = sha512_s2n_bignum(dom2_buffer || signature[0:31] || public_key || message).

  // Step: rfc8032 5.1.7.3
  // Recall, we must compute [S]B - [k]A'.
  // First negate A'. Point negation for the twisted edwards curve when points
  // are represented in the extended coordinate system is simply:
  //   -(X,Y,Z,T) = (-X,Y,Z,-T).
  // See "Twisted Edwards curves revisited" https://ia.cr/2008/522.
  // In standard coordinates, that is simply negating the x coordinate.
  // See rfc8032 5.1.4.
  bignum_neg_p25519(A, A);

  // Compute R_computed <- [S]B - [k]A'.
  uint64_t R_computed[8];
  uint8_t R_computed_encoded[32];
  bignum_mod_n25519(k, 8, k);
  edwards25519_scalarmuldouble_selector(R_computed, k, A, signature[32:63]);
  edwards25519_encode(R_computed_encoded, R_computed);                            
                                  
  // Comparison [S]B - [k]A' =? R_expected.
  return memcmp(R_computed_encoded, signature[0:31], sizeof(R_computed_encoded)) == 0;
}
```

```
size_t dom2_common(
    uint8_t dom2_buffer[MAX_DOM2_SIZE], const uint64_t phflag,
    const uint8_t *context, size_t context_len) {
    
    // DOM2_PREFIX[0:32] = "SigEd25519 no Ed25519 collisions"
    dom2_buffer [0:(32 + 1 + 1 + context+len - 1)] =
        DOM2_PREFIX || (uint8_t) phflag || (uint8_t) ctx_len || context[0:ctx_len - 1];
    return 32 + 1 + 1 + ctx_len;
}
```

### Pure Ed25519

```
int ed25519_sign_no_self_test_s2n_bignum(
    uint8_t out_sig[ED25519_SIGNATURE_LEN], const uint8_t *message,
    size_t message_len, const uint8_t private_key[ED25519_PRIVATE_KEY_LEN]) {

  ed25519_sign_common(out_sig, message, message_len, private_key, NULL, 0);
  return 1;
}
```

```
int ed25519_verify_no_self_test_s2n_bignum(
    const uint8_t *message, size_t message_len,
    const uint8_t signature[ED25519_SIGNATURE_LEN],
    const uint8_t public_key[ED25519_PUBLIC_KEY_LEN]) {
  
  return ed25519_verify_common(
    message, message_len, signature[ED25519_SIGNATURE_LEN],
    public_key[ED25519_PUBLIC_KEY_LEN], NULL, 0);
}
```

###  Ed25519ctx

```
int ed25519ctx_sign_no_self_test_s2n_bignum(
    uint8_t out_sig[ED25519_SIGNATURE_LEN], const uint8_t *message,
    size_t message_len, const uint8_t private_key[ED25519_PRIVATE_KEY_LEN],
    const uint8_t *context, size_t context_len) {

  // Ed25519ctx requires a non-empty context at most 255 bytes long
  if (ctx_len = 0 || ctx_len > 255) {
     return 0;
  }
  uint8_t dom2_buffer[MAX_DOM2_SIZE];
  size_t dom2_buffer_len = dom2_common(dom2_buffer, 0, context, context_len);

  ed25519_sign_common(out_sig, message, message_len, private_key,
    dom2_buffer, dom2_buffer_len);
  return 1;
}
```

```
int ed25519ctx_verify_no_self_test_s2n_bignum(
    const uint8_t *message, size_t message_len,
    const uint8_t signature[ED25519_SIGNATURE_LEN],
    const uint8_t public_key[ED25519_PUBLIC_KEY_LEN], const uint8_t *context,
    size_t context_len) {
  
  // Ed25519ctx requires a non-empty context at most 255 bytes long
  if (ctx_len = 0 || ctx_len > 255) {
     return 0;
  }
  uint8_t dom2_buffer[MAX_DOM2_SIZE];
  size_t dom2_buffer_len = dom2_common(dom2_buffer, 0, context, context_len);
  
  return ed25519_verify_common(
    message, message_len, signature[ED25519_SIGNATURE_LEN],
    public_key[ED25519_PUBLIC_KEY_LEN], dom2_buffer, dom2_buffer_len);
}
```

###  Ed25519ph

```
int ed25519ph_sign_no_self_test_s2n_bignum(
    uint8_t out_sig[ED25519_SIGNATURE_LEN], const uint8_t *message,
    size_t message_len, const uint8_t private_key[ED25519_PRIVATE_KEY_LEN],
    const uint8_t *context, size_t context_len) {

  // Ed25519ph requires a context at most 255 bytes long
  if (ctx_len > 255) {
      return 0;
  }
  uint8_t dom2_buffer[MAX_DOM2_SIZE];
  size_t dom2_buffer_len = dom2_common(dom2_buffer, 1, context, context_len);

  // Pre-hashing for Ed25519ph
  uint8_t digest[SHA512_DIGEST_LEN];
  digest[0:64] = sha512_s2n_bignum(message);

  ed25519_sign_common(out_sig, digest, SHA512_DIGEST_LEN, private_key,
    dom2_buffer, dom2_buffer_len);
  return 1;
}
```

```
int ed25519ph_verify_no_self_test_s2n_bignum(
    const uint8_t *message, size_t message_len,
    const uint8_t signature[ED25519_SIGNATURE_LEN],
    const uint8_t public_key[ED25519_PUBLIC_KEY_LEN], const uint8_t *context,
    size_t context_len) {

  // Ed25519ph requires a context at most 255 bytes long
  if (ctx_len > 255) {
      return 0;
  }
  uint8_t dom2_buffer[MAX_DOM2_SIZE];
  size_t dom2_buffer_len = dom2_common(dom2_buffer, 1, context, context_len);

  // Pre-hashing for Ed25519ph
  uint8_t digest[SHA512_DIGEST_LEN];
  digest[0:64] = sha512_s2n_bignum(message);
  
  return ed25519_verify_common(
    digest, SHA512_DIGEST_LEN, signature[ED25519_SIGNATURE_LEN],
    public_key[ED25519_PUBLIC_KEY_LEN], dom2_buffer, dom2_buffer_len);
}
```

## Integration into AWS-LC

### Key generation

```
void ED25519_keypair_from_seed(uint8_t out_public_key[ED25519_PUBLIC_KEY_LEN],
  uint8_t out_private_key[ED25519_PRIVATE_KEY_LEN],
  const uint8_t seed[ED25519_SEED_LEN]) {

  boringssl_ensure_eddsa_self_test();

#if defined(CURVE25519_S2N_BIGNUM_CAPABLE)
  ed25519_public_key_from_seed_s2n_bignum(out_public_key, seed);
#else
  // Existing non-s2n_bignum code.
  ...
#endif

  // Encoded public key is a suffix in the private key. Avoids having to
  // generate the public key from the private key when signing.
  OPENSSL_STATIC_ASSERT(ED25519_PRIVATE_KEY_LEN == (ED25519_SEED_LEN + ED25519_PUBLIC_KEY_LEN), ed25519_parameter_length_mismatch)
  OPENSSL_memcpy(out_private_key, seed, ED25519_SEED_LEN);
  OPENSSL_memcpy(out_private_key + ED25519_SEED_LEN, out_public_key,
    ED25519_PUBLIC_KEY_LEN);
}
```

### Pure Ed25519

```
int ED25519_sign(uint8_t out_sig[ED25519_SIGNATURE_LEN],
                 const uint8_t *message, size_t message_len,
                 const uint8_t private_key[ED25519_PRIVATE_KEY_LEN]) {
  FIPS_service_indicator_lock_state();
  boringssl_ensure_eddsa_self_test();
#if defined(CURVE25519_S2N_BIGNUM_CAPABLE)
  int res =
      ed25519_sign_no_self_test_s2n_bignum(out_sig, message, message_len, private_key);
#else
  int res =
      ED25519_sign_no_self_test(out_sig, message, message_len, private_key);
#endif
  FIPS_service_indicator_unlock_state();
  if (res) {
    FIPS_service_indicator_update_state();
  }
  return res;
}
```

```
int ED25519_verify(const uint8_t *message, size_t message_len,
                   const uint8_t signature[ED25519_SIGNATURE_LEN],
                   const uint8_t public_key[ED25519_PUBLIC_KEY_LEN]) {
  FIPS_service_indicator_lock_state();
  boringssl_ensure_eddsa_self_test();
#if defined(CURVE25519_S2N_BIGNUM_CAPABLE)
  int res =
      ed25519_verify_no_self_test_s2n_bignum(message, message_len, signature, public_key);
#else
  int res =
      ED25519_verify_no_self_test(message, message_len, signature, public_key);
#endif
  FIPS_service_indicator_unlock_state();
  if(res) {
    FIPS_service_indicator_update_state();
  }
  return res;
}
```

### Ed25519ctx

```
int ED25519ctx_sign(uint8_t out_sig[ED25519_SIGNATURE_LEN],
                    const uint8_t *message, size_t message_len,
                    const uint8_t private_key[ED25519_PRIVATE_KEY_LEN],
                    const uint8_t *context, size_t context_len) {
  FIPS_service_indicator_lock_state();
  boringssl_ensure_eddsa_self_test();
#if defined(CURVE25519_S2N_BIGNUM_CAPABLE)
  int res = ed25519ctx_sign_no_self_test_s2n_bignum(out_sig, message, message_len,
                                         private_key, context, context_len);
#else
  int res = ED25519ctx_sign_no_self_test(out_sig, message, message_len,
                                         private_key, context, context_len);
#endif
  FIPS_service_indicator_unlock_state();
  return res;
}
```

```
int ED25519ctx_verify(const uint8_t *message, size_t message_len,
                      const uint8_t signature[ED25519_SIGNATURE_LEN],
                      const uint8_t public_key[ED25519_PUBLIC_KEY_LEN],
                      const uint8_t *context, size_t context_len) {
  FIPS_service_indicator_lock_state();
  boringssl_ensure_eddsa_self_test();
#if defined(CURVE25519_S2N_BIGNUM_CAPABLE)
  int res = ed25519ctx_verify_no_self_test_s2n_bignum(message, message_len, signature,
                                           public_key, context, context_len);
#else
  int res = ED25519ctx_verify_no_self_test(message, message_len, signature,
                                           public_key, context, context_len);
#endif
  FIPS_service_indicator_unlock_state();
  return res;
}
```

### Ed25519ph

```
int ED25519ph_sign(uint8_t out_sig[ED25519_SIGNATURE_LEN],
                   const uint8_t *message, size_t message_len,
                   const uint8_t private_key[ED25519_PRIVATE_KEY_LEN],
                   const uint8_t *context, size_t context_len) {
  FIPS_service_indicator_lock_state();
  boringssl_ensure_hasheddsa_self_test();
#if defined(CURVE25519_S2N_BIGNUM_CAPABLE)
  int res = ed25519ph_sign_no_self_test_s2n_bignum(out_sig, message, message_len,
                                        private_key, context, context_len);
#else
  int res = ED25519ph_sign_no_self_test(out_sig, message, message_len,
                                        private_key, context, context_len);
#endif
  FIPS_service_indicator_unlock_state();
  if (res) {
    FIPS_service_indicator_update_state();
  }
  return res;
}
```

```
int ED25519ph_verify(const uint8_t *message, size_t message_len,
                     const uint8_t signature[ED25519_SIGNATURE_LEN],
                     const uint8_t public_key[ED25519_PUBLIC_KEY_LEN],
                     const uint8_t *context, size_t context_len) {
  FIPS_service_indicator_lock_state();
  boringssl_ensure_hasheddsa_self_test();
#if defined(CURVE25519_S2N_BIGNUM_CAPABLE)
  int res = ed25519ph_verify_no_self_test_s2n_bignum(message, message_len, signature,
                                          public_key, context, context_len);
#else
  int res = ED25519ph_verify_no_self_test(message, message_len, signature,
                                          public_key, context, context_len);
#endif
  FIPS_service_indicator_unlock_state();
  if (res) {
    FIPS_service_indicator_update_state();
  }
  return res;
}
```

## Specifications of top-level routines

The key generation is the same as Integration Plan Version 1.

```
int ed25519_public_key_from_seed_s2n_bignum (
  uint8_t out_public_key[ED25519_PUBLIC_KEY_LEN],
  const uint8_t seed[ED25519_SEED_LEN])
Pre:
  `**seed**` contains `**seed_v**` and `**LENGTH seed_v = ED25519_SEED_LEN**`
Post:
  `**out_public_key**` contains `**public_key_of_seed seed_v**`
```

### Pure Ed25519

```
int ED25519_sign_no_self_test_s2n_bignum(
    uint8_t out_sig[ED25519_SIGNATURE_LEN], const uint8_t *message,
    size_t message_len, const uint8_t private_key[ED25519_PRIVATE_KEY_LEN])
Pre:
  `**message**` contains `**m**` and `**message_len = LENGTH m**`
  `**private_key**` contains `**seed_v ++ bytelist_A**` and
    `**LENGTH private_key = 64**` and `**bytelist_A = public_key_of_seed seed_v**`
Post:
  return `**1**` and `**out_sig**` contains `**sign 0 [] seed_v m**`
```

```
int ED25519_verify_no_self_test_s2n_bignum(
    const uint8_t *message, size_t message_len,
    const uint8_t signature[ED25519_SIGNATURE_LEN],
    const uint8_t public_key[ED25519_PUBLIC_KEY_LEN])
Pre:
  `**message**` contains `**m**` and `**message_len = LENGTH m**`
  `**signature**` contains `**sig**` and `**LENGTH sig = ED25519_SIGNATURE_LEN**`
  `**public_key**` contains `**bytelist_A**` and `**LENGTH bytelist_A = ED25519_PUBLIC_KEY_LEN**`
Post: 
  if `**verify_args_valid bytelist_A sig** **/\** **verify 0 [] bytelist_A sig m**`
  then return 1
  else return 0
```

### Ed25519ctx

```
int ED25519ctx_sign_no_self_test_s2n_bignum(
    uint8_t out_sig[ED25519_SIGNATURE_LEN], const uint8_t *message,
    size_t message_len, const uint8_t private_key[ED25519_PRIVATE_KEY_LEN],
    const uint8_t *context, size_t context_len)
Pre:
  `**message**` contains `**m**` and `**message_len = LENGTH m**`
  `**private_key**` contains `**seed_v ++ bytelist_A**` and
    `**LENGTH private_key = 64**` and `**bytelist_A = public_key_of_seed seed_v**`
  `**ctx**` contains `**ctxt**` and `**LENGTH ctxt = ctx_len**`
Post: 
  if `**0 < ctx_len <= 255** ` then return `**1**` and `**out_sig**` contains `**sign 1 ctxt seed_v m**`
  else return `**0**`
```

```
int ED25519ctx_verify_no_self_test_s2n_bignum(
    const uint8_t *message, size_t message_len,
    const uint8_t signature[ED25519_SIGNATURE_LEN],
    const uint8_t public_key[ED25519_PUBLIC_KEY_LEN], const uint8_t *context,
    size_t context_len)
Pre:
  `**message**` contains `**m**` and `**message_len = LENGTH m**`
  `**signature**` contains `**sig**` and `**LENGTH sig = ED25519_SIGNATURE_LEN**`
  `**public_key**` contains `**bytelist_A**` and `**LENGTH bytelist_A = ED25519_PUBLIC_KEY_LEN**`
  `**ctx**` contains `**ctxt**` and `**LENGTH ctxt = ctx_len**`
Post: 
  if `**0 < ctx_len <= 255** **/\** **verify_args_valid bytelist_A sig** **/\** **verify 1 ctxt bytelist_A sig m**`
  then return 1
  else return 0
```

### Ed25519ph

```
int ED25519ph_sign_no_self_test_s2n_bignum(
    uint8_t out_sig[ED25519_SIGNATURE_LEN], const uint8_t *message,
    size_t message_len, const uint8_t private_key[ED25519_PRIVATE_KEY_LEN],
    const uint8_t *context, size_t context_len)
Pre:
  `**message**` contains `**m**` and `**message_len = LENGTH m**`
  `**private_key**` contains `**seed_v ++ bytelist_A**` and
    `**LENGTH private_key = 64**` and `**bytelist_A = public_key_of_seed seed_v**`
  `**ctx**` contains `**ctxt**` and `**LENGTH ctxt = ctx_len**`
Post: 
  if `**ctx_len <= 255** ` then return `**1**` and `**out_sig**` contains `**sign 2 ctxt seed_v m**`
  else return `**0**`
```

```
int ED25519ph_verify_no_self_test_s2n_bignum(
    const uint8_t *message, size_t message_len,
    const uint8_t signature[ED25519_SIGNATURE_LEN],
    const uint8_t public_key[ED25519_PUBLIC_KEY_LEN], const uint8_t *context,
    size_t context_len)
Pre:
  `**message**` contains `**m**` and `**message_len = LENGTH m**`
  `**signature**` contains `**sig**` and `**LENGTH sig = ED25519_SIGNATURE_LEN**`
  `**public_key**` contains `**bytelist_A**` and `**LENGTH bytelist_A = ED25519_PUBLIC_KEY_LEN**`
  `**ctx**` contains `**ctxt**` and `**LENGTH ctxt = ctx_len**`
Post: 
  if `**ctx_len <= 255** **/\** **verify_args_valid bytelist_A sig** **/\** **verify 2 ctxt bytelist_A sig m**`
  then return 1
  else return 0
```
