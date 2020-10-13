
/*	File: aes128gcm.c
 *	Synopsis: AES encryption with 128 bit key in GCM mode
 *	Author: yury.shukhrov@gmail.com
 *	Date: 24.11.2014
 */

#include "aes128gcm.h"

#define BIT(x) (1 << (x))

 /* Shifts right 16 byte block */
void shift_right_block(uint8_t* v) {
	uint32_t val;

	val = bit_32_to_int(v + 12);
	val >>= 1;
	if (v[11] & 0x01)
		val |= 0x80000000;
	int_to_32_bit(v + 12, val);

	val = bit_32_to_int(v + 8);
	val >>= 1;
	if (v[7] & 0x01)
		val |= 0x80000000;
	int_to_32_bit(v + 8, val);

	val = bit_32_to_int(v + 4);
	val >>= 1;
	if (v[3] & 0x01)
		val |= 0x80000000;
	int_to_32_bit(v + 4, val);

	val = bit_32_to_int(v);
	val >>= 1;
	int_to_32_bit(v, val);
}

/* Multiplication in GF(2^128) */
static void gf_mult(const uint8_t* x, const uint8_t* y, uint8_t* z) {
	uint8_t v[16];
	int i, j;

	memset(z, 0, 16); /* Z_0 = 0^128 */
	memcpy(v, y, 16); /* V_0 = Y */

	for (i = 0; i < 16; i++) {
		for (j = 0; j < 8; j++) {
			if (x[i] & BIT(7 - j)) {
				/* Z_(i + 1) = Z_i XOR V_i */
				xor_block(z, v);
			}
			else {
				/* Z_(i + 1) = Z_i */
			}

			if (v[15] & 0x01) {
				/* V_(i + 1) = (V_i >> 1) XOR R */
				shift_right_block(v);
				/* R = 11100001 || 0^120 */
				v[0] ^= 0xe1;
			}
			else {
				/* V_(i + 1) = V_i >> 1 */
				shift_right_block(v);
			}
		}
	}
}

/* XOR's two 16 byte blocks and writes the result to the destination*/
void xor_block(uint8_t* dst, const uint8_t* src) {
	uint32_t* d = (uint32_t*)dst;
	uint32_t* s = (uint32_t*)src;
	*d++ ^= *s++;
	*d++ ^= *s++;
	*d++ ^= *s++;
	*d++ ^= *s++;
}

/* Receives a pointer to a word (32 bit/4 byte).
   Converts 32 bit word to an integer base 10 */
uint32_t bit_32_to_int(uint8_t* a) {
	// Note that we only work on the part that pointer is pointing
	return (a[0] << 24) | (a[1] << 16) | (a[2] << 8) | a[3];
}

/* Given an integer value, we use it to modify the last 32 bits of the supplied bit string.
We replace the last 32 bits of the supplied bit string with the binary value of integer */
void int_to_32_bit(uint8_t* a, uint32_t val) {
	a[0] = (val >> 24) & 0xff;
	a[1] = (val >> 16) & 0xff;
	a[2] = (val >> 8) & 0xff;
	a[3] = val & 0xff;
}

/* Receives a pointer to a 64 bit string.
Converts 64 bit string to an integer base 10 */
uint64_t bit_64_to_int(const uint8_t* a) {
	return (((uint64_t)a[0]) << 56) | (((uint64_t)a[1]) << 48) |
		(((uint64_t)a[2]) << 40) | (((uint64_t)a[3]) << 32) |
		(((uint64_t)a[4]) << 24) | (((uint64_t)a[5]) << 16) |
		(((uint64_t)a[6]) << 8) | ((uint64_t)a[7]);
}

/* Given an integer value, we use it to modify the last 64 bits of the supplied bit string.
We replace the last 64 bits of the supplied bit string with the binary value of integer */
void int_to_64_bit(uint8_t* a, uint64_t val) {
	a[0] = val >> 56;
	a[1] = val >> 48;
	a[2] = val >> 40;
	a[3] = val >> 32;
	a[4] = val >> 24;
	a[5] = val >> 16;
	a[6] = val >> 8;
	a[7] = val & 0xff;
}

/* Incrementing function:
   Receives a block of bytes and increments the rightmost 32 bit = 4 byte */
void inc_32_bit(uint8_t* block) {
	uint32_t val = bit_32_to_int(block + 16 - 4);
	int_to_32_bit(block + 16 - 4, ++val);
}

/* Allocates 16 bytes of space for H and returns a pointer to it,
   Generates a hash subkey for GHASH function.
   Parameters:
   AES 128 bit key and the handle of H.*/
void init_hash_subkey(const uint8_t* key, uint8_t** H) {
	(*H) = (uint8_t*)calloc(16, sizeof(uint8_t));
	aes128e((*H), (*H), key);
}

/* Initializes J_0 - pre counter block by concatinating 31 x 0 and 1.
   Parameters:
   IV - initialization vector and a handle of J. */
void init_pre_counter_block(const uint8_t* iv, uint8_t** J) {
	(*J) = (uint8_t*)calloc(16, sizeof(uint8_t));
	memcpy((*J), iv, 12 * sizeof(uint8_t));
	(*J)[15] = 0x01;
}

/* Prapares data for GCTR procedure. If the input string bit length is zero, no encryption will be applied.
   The ciphertext array will be also empty. If the lenth is non-zero, then it copies J_0 to icb and performs inc_32.
   Only then GCTR encryption starts.
   Parameters:
   key - AES 128 bit key, J - pre counter block, in - plaintext, in_len - plaintext length, out - ciphertext.
   */
void prepare_gctr(uint8_t* key, const uint8_t* J, const uint8_t* in, size_t in_len, uint8_t* out) {
	uint8_t icb[16];

	/* No encryption if length is null*/
	if (in_len == 0) {
		return;
	}

	/* ICB = J_0*/
	memcpy(icb, J, 16 * sizeof(uint8_t));
	/* ICB ++ */
	inc_32_bit(icb);
	gctr(key, icb, in, in_len, out);
}

/* Encrypts CB_i using AES 128 bit key and then XOR's with X_i - 128 bit string.
   For each 128 bit string in input, CB is incremented, encrypted and XORed with this bit string.
   Parameters:
   key - AES 128 bit key, icb - initial counter block,
   in - array of 16 * n bytes, in_len - n 16 byte rows, out - encrypted 16 * n bytes.
   */
void gctr(uint8_t* key, const uint8_t* icb, const uint8_t* in, size_t in_len, uint8_t* out) {

	// Stores initially incremented J_0 value and gets incremented with each iteration
	uint8_t cb[16];
	// Keeps track of 16 byte blocks for input
	const uint8_t* in_pos = in;
	// Keeps track of 16 byte blocks for output
	uint8_t* out_pos = out;

	// If length is 0 no encryption needed.
	if (in_len == 0)
		return;
	// cb = icb
	memcpy(cb, icb, 16);

	for (size_t i = 0; i < in_len; i++) {
		// Encrypt 16 byte of CB_i using AES 128 bit key and write to out_pos
		aes128e(out_pos, cb, key);
		// XOR the encrypted CB_i with X_i
		xor_block(out_pos, in_pos);
		// Point to the next 16 byte block of input
		in_pos += 16;
		// Point to the next 16 byte block of output
		out_pos += 16;
		// Increment CB_i
		inc_32_bit(cb);
	}
}

/* Prepares data for GHASH procedure. If the encrypted part is non-zero, both encrypted part and
   additional authentication data will be hashed and merged into a single 128 bit tag.
   The function performs the hashing of aad and stores the result into S, then it does the same for the encrypted part.
   At the end it receives a concatination of of both hashes combined with zeros and
   binary representation of len(A) and len(C) in 64 bits.
   Parameters:
   H - hash subkey, aad - additional authentication data, aad_len - aad lenth multiple of 16 bytes,
   crypt - 16 * n bytes, crypt_len - n rows of 16 byte, S - result of GHASH.
*/
void prepare_ghash(const uint8_t* H, const uint8_t* aad, size_t aad_len,
	const uint8_t* crypt, size_t crypt_len, uint8_t** S) {
	(*S) = (uint8_t*)calloc(16, sizeof(uint8_t));

	uint8_t len_buf[16];

	/*
	* u = 128 * ceil[len(C)/128] - len(C)
	* v = 128 * ceil[len(A)/128] - len(A)
	* S = GHASH_H(A || 0^v || C || 0^u || [len(A)]_64 || [len(C)]_64)
	* (i.e., zero padded to block size A || C and lengths of each in bits)
	*/

	// Hashing the aad block, writing to S
	ghash(H, aad, aad_len, (*S));
	// Hashing the encrypted block, writing to S
	ghash(H, crypt, crypt_len, (*S));
	// [len(A)]_64
	int_to_64_bit(len_buf, aad_len * 16 * 8);
	// [len(C)]_64
	int_to_64_bit(len_buf + 8, crypt_len * 16 * 8);
	// S = GHASH_H(A || 0^v || C || 0^u || [len(A)]_64 || [len(C)]_64)
	ghash(H, len_buf, 1, (*S));
}

/* Performs the hashing */
void ghash(const uint8_t* h, const uint8_t* aad, size_t aad_len, uint8_t* out) {

	// Tracks the pointer position in aad byte array
	const uint8_t* aad_pos = aad;
	uint8_t tmp[16];

	for (size_t i = 0; i < aad_len; i++) {
		// XOR's aad[i] with out block
		xor_block(out, aad_pos);
		// Points to the next 16 bytes of aad block
		aad_pos += 16;

		/* Dot operation:
		 * Multiplication operation for binary Galois (finite) field of
		 * 2^128 elements */
		gf_mult(out, h, tmp);
		memcpy(out, tmp, 16);
	}
}

/* Under the 16-byte (128-bit) key "k",
and the 12-byte (96-bit) initial value "IV",
encrypt the plaintext "plaintext" and store it at "ciphertext".
The length of the plaintext is a multiple of 16-byte (128-bit) given by len_p (e.g., len_p = 2 for a 32-byte plaintext).
The length of the ciphertext "ciphertext" is len_p*16 bytes.
The authentication tag is obtained by the 16-byte tag "tag".
For the authentication an additional data "add_data" can be added.
The number of blocks for this additional data is "len_ad" (e.g., len_ad = 1 for a 16-byte additional data).
*/
void aes128gcm_enc(unsigned char* ciphertext, unsigned char* tag, const unsigned char* k,
	const unsigned char* IV, const unsigned char* plaintext,
	const unsigned long block_len, const unsigned char* add_data, const unsigned long add_len) {

	// H = CIPH_K(0^128)
	uint8_t* H;

	// J = IV || 0^31 || 1
	uint8_t* J;

	// S = GHASH_H(A||0^v||C||0^u||[len(A)]_64||[len(C)]_64)
	uint8_t* S;

	// Generate the hash subkey for the GHASH function
	init_hash_subkey(k, &H);

	// Generate pre-counter block J
	init_pre_counter_block(IV, &J);

	// ciphertext = GCTR_K(inc_32(J), plaintext)
	prepare_gctr((uint8_t*)k, J, plaintext, block_len, ciphertext);

	// S = GHASH_H(A||0^v||C||0^u||[len(A)]_64||[len(C)]_64)	
	prepare_ghash(H, add_data, add_len, ciphertext, block_len, &S);

	// tag = MSB_t(GCTR_K(J, S)) 
	gctr((uint8_t*)k, J, S, 1, tag);

	// Memory clean up
	free(H); free(J); free(S);
}



void aes128gcm_dec(unsigned char* plaintext, unsigned char* tag, const unsigned char* k,
	const unsigned char* IV, const unsigned char* ciphertext,
	const unsigned long block_len, const unsigned char* add_data, const unsigned long add_len) {

	// H = CIPH_K(0^128)
	uint8_t* H;

	// J = IV || 0^31 || 1
	uint8_t* J;

	// S = GHASH_H(A||0^v||C||0^u||[len(A)]_64||[len(C)]_64)
	uint8_t* S;

	// Generate the hash subkey for the GHASH function
	init_hash_subkey(k, &H);

	// Generate pre-counter block J
	init_pre_counter_block(IV, &J);

	// ciphertext = GCTR_K(inc_32(J), plaintext)
	prepare_gctr((uint8_t*)k, J, ciphertext, block_len, plaintext);

	// S = GHASH_H(A||0^v||C||0^u||[len(A)]_64||[len(C)]_64)	
	prepare_ghash(H, add_data, add_len, ciphertext, block_len, &S);

	// tag = MSB_t(GCTR_K(J, S)) 
	gctr((uint8_t*)k, J, S, 1, tag);

	// Memory clean up
	free(H); free(J); free(S);
}