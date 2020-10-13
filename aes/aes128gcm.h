/*	File: aes128gcm.h
 *	Synopsis: AES encryption with 128 bit key in GCM mode
 *	Author: yury.shukhrov@gmail.com
 *	Date: 24.11.2014
 */

#include <stdint.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include "aes128e.h"

void aes128gcm_enc(unsigned char* ciphertext, unsigned char* tag, const unsigned char* k,
	const unsigned char* IV, const unsigned char* plaintext,
	const unsigned long block_len, const unsigned char* add_data, const unsigned long add_len);
void aes128gcm_dec(unsigned char* plaintext, unsigned char* tag, const unsigned char* k,
	const unsigned char* IV, const unsigned char* ciphertext,
	const unsigned long block_len, const unsigned char* add_data, const unsigned long add_len);

void shift_right_block(uint8_t* v);
static void gf_mult(const uint8_t* x, const uint8_t* y, uint8_t* z);
void xor_block(uint8_t* dst, const uint8_t* src);
uint32_t bit_32_to_int(uint8_t* a);
void int_to_32_bit(uint8_t* a, uint32_t val);
uint64_t bit_64_to_int(const uint8_t* a);
void int_to_64_bit(uint8_t* a, uint64_t val);
void inc_32_bit(uint8_t* block);
void init_hash_subkey(const uint8_t* key, uint8_t** H);
void init_pre_counter_block(const uint8_t* iv, uint8_t** J);
void prepare_gctr(uint8_t* key, const uint8_t* J, const uint8_t* in, size_t in_len, uint8_t* out);
void gctr(uint8_t* key, const uint8_t* icb, const uint8_t* in, size_t in_len, uint8_t* out);
void prepare_ghash(const uint8_t* H, const uint8_t* aad, size_t aad_len, const uint8_t* crypt, size_t crypt_len, uint8_t** S);
void ghash(const uint8_t* h, const uint8_t* x, size_t xlen, uint8_t* y);