.text

// ???TODO: use directives in _internal_s2n_bignum.h

.global	ed25519_keypair_from_seed_s2n_bignum
.balign 4
// ----------------------------------------------------------------------------
// Compute the public key A of an Ed25519 instance from the random seed
// See Ed25519 key generation in rfc8032 5.1.5
// Inputs: A[32], seed[32]
// Outputs: write the public key to A
//    extern void ed25519_keypair_from_seed_s2n_bignumed25519_keypair_from_seed_s2n_bignum (
// 						uint8_t A[ED25519_PUBLIC_KEY_LEN],
// 						const uint8_t seed[ED25519_SEED_LEN]);
//
// Standard ARM ABI: X0 = A, X1 = seed
// ----------------------------------------------------------------------------
ed25519_keypair_from_seed_s2n_bignum:

// Stack layout: X19, X20, sha[216], h[64], s_B[32], padding[8]
	stp x19, x20, [sp, #-336]!
    mov x19, x0
    mov x20, x1

// Step: rfc8032 5.1.5.1
// Compute h[0:63] = SHA-512(seed)

    add x0, sp, #16
    bl sha512_init
	add x0, sp, #16
    mov x1, x20
    mov x2, #32
    bl sha512_update
	add x0, sp, #232
	add x1, sp, #16
	bl sha512_final

// Step: rfc8032 5.1.5.2
// h[0] &= 248; // 11111000_2
// h[31] &= 127; // 01111111_2
// h[31] |= 64; // 01000000_2

	ldrb w0, [sp, #232]
	and w0, w0, #248
	strb w0, [sp, #232]
	ldrb w0, [sp, #263]
	and w0, w0, #127
	orr w0, w0, #64
	strb w0, [sp, #263]

// Step: rfc8032 5.1.5.3
// Compute [s]B and encode public key to a 32 byte octet
//   where s = h[0:31]
// uint64_t s_B[8];
// edwards25519_scalarmulbase_alt(s_B, h);

	add x0, sp, #296
	add x1, sp, #232
  	bl edwards25519_scalarmulbase_alt
  
// Step: rfc8032 5.1.5.4
// edwards25519_encode(A, s_B);

	mov x0, x19
	add x1, sp, #296
	bl edwards25519_encode

// Restore callee-saved registers
	ldp	x19, x20, [sp], #336
	ret


.balign 4
// ----------------------------------------------------------------------------
// Auxiliary function that computes the Ed25519/Ed25519ctx/Ed25519ph signature of a message
// See Ed25519 sign in rfc8032 5.1.6
// Inputs: out_sig[64], message[message_len], message_len,
//	  	private_key[64], dom2_buffer[dom2_buffer_len], dom2_buffer_len
// Pre-condition: dom2_buffer and dom2_buffer_len are correct and the message has been pre-hashed for Ed25519ph,
// 		private_key contains the seed followed by the corresponding public key
// Outputs: write the correct signature to out_sig
//    void ed25519_sign_common(
// 						uint8_t out_sig[ED25519_SIGNATURE_LEN], const uint8_t *message,
// 						size_t message_len, const uint8_t private_key[ED25519_PRIVATE_KEY_LEN],
// 						uint8_t *dom2_buffer, size_t dom2_buffer_len);
//
// Standard ARM ABI: X0 = out_sig, X1 = message, X2 = message_len,
//	 	X3 = private_key, X4 = dom2_buffer, X5 = dom2_buffer_len
// ----------------------------------------------------------------------------
ed25519_sign_common:

// Stack layout:  X19, X20, X21, X22, X23, X24, sha[216], h[64], r[64], r_B[64], k[64], padding[8]
	sub sp, sp, #528
	stp x19, x20, [sp]
	stp x21, x22, [sp, #16]
	stp x23, x24, [sp, #32]
	mov x19, x0
	mov x20, x1
	mov x21, x2
	mov x22, x3
	mov x23, x4
	mov x24, x5

// Step: rfc8032 5.1.6.1
// seed = private_key[0:31];
// Compute h[0:63] = SHA-512(seed).

    add x0, sp, #48
    bl sha512_init
	add x0, sp, #48
    mov x1, x22
    mov x2, #32
    bl sha512_update
	add x0, sp, #264
	add x1, sp, #48
	bl sha512_final

// h[0] &= 248; // 11111000_2
// h[31] &= 127; // 01111111_2
// h[31] |= 64; // 01000000_2

	ldrb w0, [sp, #264]
	and w0, w0, #248
	strb w0, [sp, #264]
	ldrb w0, [sp, #295]
	and w0, w0, #127
	orr w0, w0, #64
	strb w0, [sp, #295]

// Step: rfc8032 5.1.6.2
// prefix = h[32:63]
// uint8_t r[SHA512_DIGEST_LENGTH];
// r[0:63] = sha512_s2n_bignum(dom2_buffer || h[32:63] || message);

	add x0, sp, #48
	bl sha512_init
	cbz x24, .L1
	add x0, sp, #48
    mov x1, x23
    mov x2, x24
	bl sha512_update
.L1:
	add x0, sp, #48
    add x1, sp, #296
    mov x2, #32
	bl sha512_update
	add x0, sp, #48
    mov x1, x20
    mov x2, x21
	bl sha512_update
	add x0, sp, #328
	add x1, sp, #48
	bl sha512_final

// Step: rfc8032 5.1.6.3
// Reduce r modulo the order of the base-point B.
// bignum_mod_n25519(r, 8, r);
	add x0, sp, #328
	mov x1, #8
	mov x2, x0
	bl bignum_mod_n25519

// Compute [r]B.
// uint64_t r_B[8];
// edwards25519_scalarmulbase_alt(r_B, r);
// edwards25519_encode(out_sig, r_B);
	add x0, sp, #392
	add x1, sp, #328
	bl edwards25519_scalarmulbase_alt
	mov x0, x19
	add x1, sp, #392
	bl edwards25519_encode

// Step: rfc8032 5.1.6.4
// R = out_sig[0:31]
// A = private_key[32:63]
// uint8_t k[SHA512_DIGEST_LENGTH];
// k[0:63] = sha512_s2n_bignum(dom2_buffer || out_sig[0:31] || private_key[32:63] || message);
	add x0, sp, #48
	bl sha512_init
	cbz x24, .L2
	add x0, sp, #48
    mov x1, x23
    mov x2, x24
	bl sha512_update
.L2:
	add x0, sp, #48
    mov x1, x19
    mov x2, #32
	bl sha512_update
	add x0, sp, #48
    add x1, x22, #32
    mov x2, #32
	bl sha512_update
	add x0, sp, #48
    mov x1, x20
    mov x2, x21
	bl sha512_update
	add x0, sp, #456
	add x1, sp, #48
	bl sha512_final

// Step: rfc8032 5.1.6.5
// Compute S = r + k * s modulo the order of the base-point B
//   where s = h[0:31]
// Step: rfc8032 5.1.6.6
// out_sig = R || S
// bignum_mod_n25519(k, 8, k);
// bignum_madd_n25519_alt(out_sig + 32, k, s, r);
	add x0, sp, #456
	mov x1, #8
	mov x2, x0
	bl bignum_mod_n25519
	add x0, x19, #32
	add x1, sp, #456
	add x2, sp, #264
	add x3, sp, #328
	bl bignum_madd_n25519_alt

// Restore callee-saved registers
	ldp x19, x20, [sp]
	ldp x21, x22, [sp, #16]
	ldp x23, x24, [sp, #32]
	add sp, sp, #528 
	ret


.balign 4
// ----------------------------------------------------------------------------
// Auxiliary function that verifies the Ed25519/Ed25519ctx/Ed25519ph signature of a message
// See Ed25519 verify in rfc8032 5.1.7
// Inputs: message[message_len], message_len, signature[64],
//	  	public_key[32], dom2_buffer[dom2_buffer_len], dom2_buffer_len
// Pre-condition: dom2_buffer and dom2_buffer_len are correct and the message has been pre-hashed for Ed25519ph
// Outputs: return 1 if the verification succeeds, return 0 otherwise
//    int ed25519_verify_common(
// 						const uint8_t *message, size_t message_len,
// 						const uint8_t signature[ED25519_SIGNATURE_LEN],
//						const uint8_t public_key[ED25519_PUBLIC_KEY_LEN],
// 						uconst uint8_t *dom2_buffer, size_t dom2_buffer_len);
//
// Standard ARM ABI: X0 = message, X1 = message_len, X2 = signature,
//	 	X3 = public_key, X4 = dom2_buffer, X5 = dom2_buffer_len
// ----------------------------------------------------------------------------
ed25519_verify_common:

// Stack layout:  X19, X20, X21, X22, X23, X24, order[32], A[64], sha[216],
// 		k[64], R_computed[64], r_computed_encoded[32]
	sub sp, sp, #528
	stp x19, x20, [sp]
	stp x21, x22, [sp, #16]
	stp x23, x24, [sp, #32]
	mov x19, x0
	mov x20, x1
	mov x21, x2
	mov x22, x3
	mov x23, x4
	mov x24, x5

// Step: rfc8032 5.1.7.1
// Decode signature as:
//  - signature[0:31]: encoded point R.
//  - signature[32:63]: integer S.
// S must be in the range [0, ORDER) in order to prevent signature
// malleability. ORDER is the order of curve25519 in little-endian form.
// uint8_t order[32] = ORDER;
// if (bignum_le(32, order, 32, signature + 32)) return 0;
	mov x0, #0xd3ed
	movk	x0, #0x5cf5, lsl 16
	movk	x0, #0x631a, lsl 32
	movk	x0, #0x5812, lsl 48
	mov x1, #0x9cd6
	movk	x1, #0xa2f7, lsl 16
	movk	x1, #0xf9de, lsl 32
	movk	x1, #0x14de, lsl 48
	stp x0, x1, [sp, #48]
	mov x0, xzr
	mov x1, #1
	lsl x1, x1, #63
	stp x0, x1, [sp, #64]
	mov x0, #32
	add x1, sp, #48
	mov x2, #32
	add x3, x21, #32
	bl bignum_le
	cbnz x0, .L3

// Decode public key as A.
// uint64_t A[8];
// if (edwards25519_decode_alt(A, public_key) != 0) return 0;
	add x0, sp, #80
	mov x1, x22
	bl edwards25519_decode_alt
	cbnz x0, .L3

// Step: rfc8032 5.1.7.2
// uint8_t k[SHA512_DIGEST_LENGTH];
// k[0:63] = sha512_s2n_bignum(dom2_buffer || signature[0:31] || public_key || message).
	add x0, sp, #144
	bl sha512_init
	cbz x24, .L4
	add x0, sp, #144
    mov x1, x23
    mov x2, x24
	bl sha512_update
.L4:
	add x0, sp, #144
    mov x1, x21
    mov x2, #32
	bl sha512_update
	add x0, sp, #144
    mov x1, x22
    mov x2, #32
	bl sha512_update
	add x0, sp, #144
    mov x1, x19
    mov x2, x20
	bl sha512_update
	add x0, sp, #360
	add x1, sp, #144
	bl sha512_final

// Step: rfc8032 5.1.7.3
// Recall, we must compute [S]B - [k]A'.
// First negate A'. Point negation for the twisted edwards curve when points
// are represented in the extended coordinate system is simply:
//   -(X,Y,Z,T) = (-X,Y,Z,-T).
// See "Twisted Edwards curves revisited" https://ia.cr/2008/522.
// In standard coordinates, that is simply negating the x coordinate.
// See rfc8032 5.1.4.
// bignum_neg_p25519(A, A);
	add x0, sp, #80
	mov x1, x0
	bl bignum_neg_p25519

// Compute R_computed <- [S]B - [k]A'.
// uint64_t R_computed[8];
// uint8_t R_computed_encoded[32];
// bignum_mod_n25519(k, 8, k);
// edwards25519_scalarmuldouble_alt(R_computed, k, A, signature[32:63]);
// edwards25519_encode(R_computed_encoded, R_computed);
	add x0, sp, #360
	mov x1, #8
	mov x2, x0
	bl bignum_mod_n25519
	add x0, sp, #424
	add x1, sp, #360
	add x2, sp, #80
	add x3, x21, #32
	bl edwards25519_scalarmuldouble_alt
	add x0, sp, #488
	add x1, sp, #424
	bl edwards25519_encode
							
// Comparison [S]B - [k]A' =? R_expected.
	ldp x0, x1, [sp, #488]
	ldp x2, x3, [x21]
	cmp x0, x2
	bne .L3
	cmp x1, x3
	bne .L3
	ldp x0, x1, [sp, #504]
	ldp x2, x3, [x21, #16]
	cmp x0, x2
	bne .L3
	cmp x1, x3
	bne .L3

// return memcmp(R_computed_encoded, signature[0:31], sizeof(R_computed_encoded)) == 0;
	mov x0, #1
	b .L5
.L3:
	mov x0, xzr

// Restore callee-saved registers
.L5:
	ldp x19, x20, [sp]
	ldp x21, x22, [sp, #16]
	ldp x23, x24, [sp, #32]
	add sp, sp, #528 
	ret


.global	ed25519_sign_no_self_test_s2n_bignum
.balign 4
// ----------------------------------------------------------------------------
// Compute the (pure) Ed25519 signature of a message
// Inputs: out_sig[64], message[message_len], message_len, private_key[64]
// Pre-condition: private_key contains the seed followed by the corresponding public key
// Outputs: write the correct signature to out_sig and return 1
//    extern int ed25519_sign_no_self_test_s2n_bignum(
// 						uint8_t out_sig[ED25519_SIGNATURE_LEN], const uint8_t *message,
// 						size_t message_len, const uint8_t private_key[ED25519_PRIVATE_KEY_LEN]);
//
// Standard ARM ABI: X0 = out_sig, X1 = message, X2 = message_len, X3 = private_key
// ----------------------------------------------------------------------------
ed25519_sign_no_self_test_s2n_bignum:

// ed25519_sign_common(out_sig, message, message_len, private_key, NULL, 0);
	mov x4, xzr
	mov x5, xzr
	bl ed25519_sign_common

// return 1;
	mov x0, #1
	ret


.global	ed25519_verify_no_self_test_s2n_bignum
.balign 4
// ----------------------------------------------------------------------------
// Verify the (pure) Ed25519 signature of a message
// Inputs: message[message_len], message_len, signature[64], public_key[32]
// Outputs: return 1 if the verification succeeds, return 0 otherwise
//    extern int ed25519_verify_no_self_test_s2n_bignum(
// 						const uint8_t *message, size_t message_len,
// 						const uint8_t signature[ED25519_SIGNATURE_LEN],
//						const uint8_t public_key[ED25519_PUBLIC_KEY_LEN]);
//
// Standard ARM ABI: X0 = message, X1 = message_len, X2 = signature, X3 = public_key
// ----------------------------------------------------------------------------
ed25519_verify_no_self_test_s2n_bignum:
  
// return ed25519_verify_common(
// 		message, message_len, signature[ED25519_SIGNATURE_LEN],
//  	public_key[ED25519_PUBLIC_KEY_LEN], NULL, 0);
	mov x4, xzr
	mov x5, xzr
	bl ed25519_verify_common
	ret


.balign 4
// ----------------------------------------------------------------------------
// Compute the dom2 given an Ed25519 variant (either Ed25519ctx or Ed25519ph) and the context
// Inputs: dom2_buffer[MAX_DOM2_SIZE], phflag, context[context_len], context_len
// Pre-condition: phflag = 0 and 0 < context_len <= 255 for Ed25519ctx,
// 		phflag = 1 and context_len <= 255 for Ed25519ph
// Outputs: write dom2(phflag, context) to dom2_buffer and return dom2_buffer_len
//    size_t dom2_common(uint8_t dom2_buffer[MAX_DOM2_SIZE], const uint64_t phflag,
//					const uint8_t *context, size_t context_len);
//
// Standard ARM ABI: X0 = dom2_buffer, X1 = phflag, X2 = context, X3 = context_len
// ----------------------------------------------------------------------------
dom2_common:
// DOM2_PREFIX[0:32] = "SigEd25519 no Ed25519 collisions"
// dom2_buffer [0:(32 + 1 + 1 + context+len - 1)] =
// 		DOM2_PREFIX || (uint8_t) phflag || (uint8_t) ctx_len || context[0:ctx_len - 1];
	mov x4, #0x6953	// "Si"
	movk	x4, #0x4567, lsl #16 // "gE"
	movk	x4, #0x3264, lsl #32 // "d2"
	movk	x4, #0x3535, lsl #48 // "55"
	mov	x5, #0x3931 //"19" 
	movk	x5, #0x6e20, lsl #16 // " n"
	movk	x5, #0x206f, lsl #32 // "o "
	movk	x5, #0x6445, lsl #48 // "Ed"
	stp x4, x5, [x0]
	mov x4, #0x3532 // "25"
	movk	x4, #0x3135, lsl #16 // "51"
	movk	x4, #0x2039, lsl #32 // "9 "
	movk	x4, #0x6f63, lsl #48 // "co"
	mov x5, #0x6c6c // "ll"
	movk	x5, #0x7369, lsl #16 // "is"
	movk	x5, #0x6f69, lsl #32 // "io"
	movk	x5, #0x736e, lsl #48 // "ns"
	stp x4, x5, [x0, #16]
	strb w1, [x0, #32]
	strb w3, [x0, #33]
	add x4, x0, #34
	mov x5, xzr
	b .L6
.L7:
	ldrb w6, [x2, x5]
	strb w6, [x4, x5]
	add x5, x5, #1
.L6:
	cmp x3, x5
	bne .L7

// return 32 + 1 + 1 + ctx_len;
	add x0, x3, #34
	ret


.global	ed25519ctx_sign_no_self_test_s2n_bignum
.balign 4
// ----------------------------------------------------------------------------
// Compute the Ed25519ctx signature of a message
// Inputs: out_sig[64], message[message_len], message_len, private_key[64],
//		context[context_len], context_len
// Pre-condition: private_key contains the seed followed by the corresponding public key
// Outputs: if 0 < context_len <= 255, write the correct signature to out_sig and return 1
//		else return 0
//    extern int ed25519ctx_sign_no_self_test_s2n_bignum(
// 						uint8_t out_sig[ED25519_SIGNATURE_LEN], const uint8_t *message,
// 						size_t message_len, const uint8_t private_key[ED25519_PRIVATE_KEY_LEN],
//						const uint8_t *context, size_t context_len) ;
//
// Standard ARM ABI: X0 = out_sig, X1 = message, X2 = message_len,
//	 	X3 = private_key, X4 = context, X5 = context_len
// ----------------------------------------------------------------------------
ed25519ctx_sign_no_self_test_s2n_bignum:

// Stack layout: X19, X20, X21, X22, dom2_buffer[289], padding[15]
	stp x19, x20, [sp, #-336]!
	stp x21, x22, [sp, #16]
	mov x19, x0
	mov x20, x1
	mov x21, x2
	mov x22, x3

// Ed25519ctx requires a non-empty context at most 255 bytes long
// if (ctx_len = 0 || ctx_len > 255) return 0;
	cbz x5, .L8
	cmp x5, #255
	bhi .L8

// uint8_t dom2_buffer[MAX_DOM2_SIZE];
// x0 = dom2_common(dom2_buffer, 0, context, context_len);
	add x0, sp, #32
	mov x1, xzr
	mov x2, x4
	mov x3, x5
	bl dom2_common

// ed25519_sign_common(out_sig, message, message_len, private_key,
// 		dom2_buffer, length(dom2_buffer));
	mov x5, x0
	mov x0, x19
	mov x1, x20
	mov x2, x21
	mov x3, x22
	add x4, sp, #32
	bl ed25519_sign_common

// return 1;
	mov x0, #1
	b .L9
.L8:
	mov x0, xzr
.L9:
	ldp x21, x22, [sp, #16]
	ldp x19, x20, [sp], #336
	ret


.global	ed25519ctx_verify_no_self_test_s2n_bignum
.balign 4
// ----------------------------------------------------------------------------
// Verify the Ed25519ctx signature of a message
// Inputs: message[message_len], message_len, signature[64], public_key[32],
//		context[context_len], context_len
// Outputs: return 1 if the verification succeeds, return 0 otherwise
//    extern int ed25519ctx_verify_no_self_test_s2n_bignum(
// 						const uint8_t *message, size_t message_len,
// 						const uint8_t signature[ED25519_SIGNATURE_LEN],
//						const uint8_t public_key[ED25519_PUBLIC_KEY_LEN])
// 						const uint8_t *context, size_t context_len);
//
// Standard ARM ABI: X0 = message, X1 = message_len, X2 = signature, X3 = public_key,
//		X4 = context, X5 = context_len
// ----------------------------------------------------------------------------
ed25519ctx_verify_no_self_test_s2n_bignum:

// Stack layout: X19, X20, X21, X22, dom2_buffer[289], padding[15]
	stp x19, x20, [sp, #-336]!
	stp x21, x22, [sp, #16]
	mov x19, x0
	mov x20, x1
	mov x21, x2
	mov x22, x3

// Ed25519ctx requires a non-empty context at most 255 bytes long
// if (ctx_len = 0 || ctx_len > 255) return 0;
	cbz x5, .L10
	cmp x5, #255
	bhi .L10

// uint8_t dom2_buffer[MAX_DOM2_SIZE];
// x0 = dom2_common(dom2_buffer, 0, context, context_len);
	add x0, sp, #32
	mov x1, xzr
	mov x2, x4
	mov x3, x5
	bl dom2_common

// return ed25519_verify_common(
// 		message, message_len, signature[ED25519_SIGNATURE_LEN],
// 		public_key[ED25519_PUBLIC_KEY_LEN], dom2_buffer, length(dom2_buffer));
	mov x5, x0
	mov x0, x19
	mov x1, x20
	mov x2, x21
	mov x3, x22
	add x4, sp, #32
	bl ed25519_verify_common
	b .L11

.L10:
	mov x0, xzr
.L11:
	ldp x21, x22, [sp, #16]
	ldp x19, x20, [sp], #336
	ret
	

.global	ed25519ph_sign_no_self_test_s2n_bignum
.balign 4
// ----------------------------------------------------------------------------
// Compute the Ed25519ph signature of a message
// Inputs: out_sig[64], message[message_len], message_len, private_key[64],
//		context[context_len], context_len
// Pre-condition: private_key contains the seed followed by the corresponding public key
// Outputs: if context_len <= 255, write the correct signature to out_sig and return 1
//		else return 0
//    extern int ed25519ph_sign_no_self_test_s2n_bignum(
// 						uint8_t out_sig[ED25519_SIGNATURE_LEN], const uint8_t *message,
// 						size_t message_len, const uint8_t private_key[ED25519_PRIVATE_KEY_LEN],
//						const uint8_t *context, size_t context_len) ;
//
// Standard ARM ABI: X0 = out_sig, X1 = message, X2 = message_len,
//	 	X3 = private_key, X4 = context, X5 = context_len
// ----------------------------------------------------------------------------
ed25519ph_sign_no_self_test_s2n_bignum:

// Stack layout: X19, X20, X21, X22, dom2_buffer[289], padding[7], dom2_buffer_len[8], sha[216], digest[64], padding[8]
	sub sp, sp, #624
	stp x19, x20, [sp]
	stp x21, x22, [sp, #16]
	mov x19, x0
	mov x20, x1
	mov x21, x2
	mov x22, x3

// Ed25519ph requires a context at most 255 bytes long
//  if (ctx_len > 255) return 0;
	cmp x5, #255
	bhi .L12

// uint8_t dom2_buffer[MAX_DOM2_SIZE];
// x0 = dom2_common(dom2_buffer, 1, context, context_len);
	add x0, sp, #32
	mov x1, #1
	mov x2, x4
	mov x3, x5
	bl dom2_common
	str x0, [sp, #328]

// Pre-hashing for Ed25519ph
// uint8_t digest[SHA512_DIGEST_LENGTH];
// digest[0:64] = sha512_s2n_bignum(message);
	add x0, sp, #336
	bl sha512_init
	add x0, sp, #336
    mov x1, x20
    mov x2, x21
	bl sha512_update
	add x0, sp, #552
	add x1, sp, #336
	bl sha512_final

// ed25519_sign_common(out_sig, digest, SHA512_DIGEST_LEN, private_key,
// 		dom2_buffer, length(dom2_buffer));
	mov x0, x19
	add x1, sp, #552
	mov x2, #64
	mov x3, x22
	add x4, sp, #32
	ldr x5, [sp, #328]
	bl ed25519_sign_common

// return 1;
	mov x0, #1
	b .L13
.L12:
	mov x0, xzr
.L13:
	ldp x19, x20, [sp]
	ldp x21, x22, [sp, #16]
	add sp, sp, #624
	ret


.global	ed25519ph_verify_no_self_test_s2n_bignum
.balign 4
// ----------------------------------------------------------------------------
// Verify the Ed25519ph signature of a message
// Inputs: message[message_len], message_len, signature[64], public_key[32],
//		context[context_len], context_len
// Outputs: return 1 if the verification succeeds, return 0 otherwise
//    extern int ed25519ph_verify_no_self_test_s2n_bignum(
// 						const uint8_t *message, size_t message_len,
// 						const uint8_t signature[ED25519_SIGNATURE_LEN],
//						const uint8_t public_key[ED25519_PUBLIC_KEY_LEN])
// 						const uint8_t *context, size_t context_len);
//
// Standard ARM ABI: X0 = message, X1 = message_len, X2 = signature, X3 = public_key,
//		X4 = context, X5 = context_len
// ----------------------------------------------------------------------------
ed25519ph_verify_no_self_test_s2n_bignum:

// Stack layout: X19, X20, X21, X22, dom2_buffer[289], padding[7], dom2_buffer_len[8], sha[216], digest[64], padding[8]
	sub sp, sp, #624
	stp x19, x20, [sp]
	stp x21, x22, [sp, #16]
	mov x19, x0
	mov x20, x1
	mov x21, x2
	mov x22, x3

// Ed25519ph requires a context at most 255 bytes long
//  if (ctx_len > 255) return 0;
	cmp x5, #255
	bhi .L14

// uint8_t dom2_buffer[MAX_DOM2_SIZE];
// x0 = dom2_common(dom2_buffer, 1, context, context_len);
	add x0, sp, #32
	mov x1, #1
	mov x2, x4
	mov x3, x5
	bl dom2_common
	str x0, [sp, #328]

// Pre-hashing for Ed25519ph
// uint8_t digest[SHA512_DIGEST_LENGTH];
// digest[0:64] = sha512_s2n_bignum(message);
	add x0, sp, #336
	bl sha512_init
	add x0, sp, #336
    mov x1, x19
    mov x2, x20
	bl sha512_update
	add x0, sp, #552
	add x1, sp, #336
	bl sha512_final

// return ed25519_verify_common(
// 		digest, SHA512_DIGEST_LEN, signature[ED25519_SIGNATURE_LEN],
// 		public_key[ED25519_PUBLIC_KEY_LEN], dom2_buffer, length(dom2_buffer));
	add x0, sp, #552
	mov x1, #64
	mov x2, x21
	mov x3, x22
	add x4, sp, #32
	ldr x5, [sp, #328]
	bl ed25519_verify_common
	b .L15
.L14:
	mov x0, xzr
.L15:
	ldp x19, x20, [sp]
	ldp x21, x22, [sp, #16]
	add sp, sp, #624
	ret