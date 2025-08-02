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
	stp x19, x20, [sp, -336]!
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

	ldrb w0, [sp, 232]
	and w0, w0, #248
	strb w0, [sp, 232]
	ldrb w0, [sp, 263]
	and w0, w0, #127
	orr w0, w0, #64
	strb w0, [sp, 263]

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
	ldp	x19, x20, [sp], 336


.global	ed25519_sign_common_s2n_bignum
.balign 4
// ----------------------------------------------------------------------------
// Auxiliary function that computes the Ed25519/Ed25519ctx/Ed25519ph signature of a message
// See Ed25519 sign in rfc8032 5.1.6
// Inputs: out_sig[64], message[message_len], message_len,
//	  	private_key[64], dom2_buffer[dom2_buffer_len], dom2_buffer_len
// Outputs: if dom2_buffer and dom2_buffer_len are correct and the message has been pre-hashed for Ed25519ph,
// 		then write the correct signature to out_sig,
//		else no guarantee.
//    void ed25519_sign_common_s2n_bignum(
// 						uint8_t out_sig[ED25519_SIGNATURE_LEN], const uint8_t *message,
// 						size_t message_len, const uint8_t private_key[ED25519_PRIVATE_KEY_LEN],
// 						uint8_t *dom2_buffer, size_t dom2_buffer_len);
//
// Standard ARM ABI: X0 = out_sig, X1 = message, X2 = message_len,
//	 	X3 = private_key, X4 = dom2_buffer, X5 = dom2_buffer_len
// ----------------------------------------------------------------------------
ed25519_sign_common_s2n_bignum:

// Stack layout:  sha[216], h[64] dom2_buffer[MAX_DOM2_SIZE], dom2_buffer_len
	???
	19, x1
	20, x2
	21, x3
	22, x4


// Step: rfc8032 5.1.6.1
// seed = private_key[0:31];
// Compute h[0:63] = SHA-512(seed).

    add x0, sha loc
    bl sha512_init
	add x0, sha loc
    mov x1, x20
    mov x2, #32
    bl sha512_update
	add x0, h loc
	add x1, sha loc
	bl sha512_final

// h[0] &= 248; // 11111000_2
// h[31] &= 127; // 01111111_2
// h[31] |= 64; // 01000000_2

	ldrb w0, [sp, 232]
	and w0, w0, #248
	strb w0, [sp, 232]
	ldrb w0, [sp, 263]
	and w0, w0, #127
	orr w0, w0, #64
	strb w0, [sp, 263]

// Step: rfc8032 5.1.6.2
// prefix = h[32:63]
// uint8_t r[SHA512_DIGEST_LENGTH];
// r[0:63] = sha512_s2n_bignum(dom2_buffer || h[32:63] || message);

	add x0, sha loc
	bl sha512_init
	cbz buf_len reg .L1
	add x0, sha loc
    mov x1, dom2_buffer reg
    mov x2, dom2_buffer_len reg
	bl sha512_update
.L1
	add x0, sha loc
    mov x1, h loc +32
    mov x2, #32
	bl sha512_update
	add x0, sha loc
    mov x1, message loc
    mov x2, message_len reg
	bl sha512_update
	add x0, r loc
	add x1, sha loc
	bl sha512_final

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
uint8_t k[SHA512_DIGEST_LENGTH];
k[0:63] = sha512_s2n_bignum(dom2_buffer || out_sig[0:31] || private_key[32:63] || message);

// Step: rfc8032 5.1.6.5
// Compute S = r + k * s modulo the order of the base-point B
//   where s = h[0:31]
// Step: rfc8032 5.1.6.6
// out_sig = R || S
bignum_mod_n25519(k, 8, k);
bignum_madd_n25519_selector(out_sig + 32, k, s, r);