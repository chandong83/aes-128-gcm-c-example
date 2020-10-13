#include <iostream>
#include <string.h>
#include "aes128e.h"
#include "aes128gcm.h"

//비교함수
int compare(const void* a, const void* b, size_t len)
{
	const unsigned char* aa = (unsigned char*)a;
	const unsigned char* bb = (unsigned char*)b;
	size_t i;
	volatile unsigned char res = 0;
	printf("\n");
	for (res = 0, i = 0; i < len; i++) {
		res |= (aa[i] ^ bb[i]);
	}
	return res;
}

//암호 키
const unsigned char key[16] = {	0x98, 0xff, 0xf6, 0x7e, 0x64, 0xe4, 0x6b, 0xe5, 0xee, 0x2e, 0x05, 0xcc, 0x9a, 0xf6, 0xd0, 0x12 };
//1회용 초기화 키 Nonce
const unsigned char IV[12] = { 0x2d, 0xfb, 0x42, 0x9a, 0x48, 0x69, 0x7c, 0x34, 0x00, 0x6d, 0xa8, 0x86 };

//평문 데이터
const unsigned char plaintext[16] = "Hello world";

//추가 인증 데이터 Additional authenticated data
const unsigned char add_data[16] = { 0xa0, 0xca, 0x58, 0x61, 0xc0, 0x22, 0x6c, 0x5b, 0x5a, 0x65, 0x14, 0xc8, 0x2b, 0x77, 0x81, 0x5a };

//tag 검증용 데이터 GMAC
const unsigned char tag_ref[16] = {	0xE9, 0x11, 0x99, 0x69, 0x98, 0xAD, 0xFA, 0x61, 0x2E, 0xFF, 0x09, 0x71, 0x01, 0x33, 0x6C, 0x1B };

//암호화 검증용 데이터
const unsigned char ciphertext_ref[16] = { 0xA3, 0xF3, 0x99, 0x95, 0xE5, 0xF4, 0x2B, 0xD1, 0x25, 0x35, 0x12, 0x09, 0xC8, 0x94, 0xDD, 0x1D };

int main()
{
	unsigned char ciphertext[16];
	unsigned char decrypted_plaintext[16];
	unsigned char tag[16];
	unsigned char decrypted_tag[16];
	unsigned int block_len = 1;
	unsigned int add_len = 1;

	printf("========================================\n");
	printf("Encrpytion :\n");
	printf("----------------------------------------\n");

	//암호화!!
	aes128gcm_enc(ciphertext, tag, key, IV, plaintext, block_len, add_data, add_len);		

	if (ciphertext != NULL) {
		printf("ciphertext %s ", !compare(ciphertext, ciphertext_ref, (block_len) * 16) ? "PASS" : "FAIL");
		for (int i = 0; i < 16 * block_len; i++) {
			printf("0x%02X ", ciphertext[i]);
		}
		printf("\n");
	}
	if (tag != NULL) {
		printf("Bytes : ");
		printf("tag result : %s\n", !compare(tag, tag_ref, 16) ? "PASS" : "FAIL");
		for (int i = 0; i < 16 * block_len; i++) {
			printf("0x%02X ", tag[i]);
		}
		printf("\n");
	}

	printf("\n========================================\n");
	printf("Decrpytion :\n");
	printf("----------------------------------------\n");

	//복호화!!
	aes128gcm_dec(decrypted_plaintext, decrypted_tag, key, IV, ciphertext, block_len, add_data, add_len);
	
	if (decrypted_plaintext != NULL) {
		printf("decrypted_plaintext result : %s\n", compare(decrypted_plaintext, plaintext, (block_len) * 16)==0 ? "PASS" : "FAIL");
		printf("STRING : %s \n", decrypted_plaintext);
		printf("Bytes : ");
		for (int i = 0; i < 16 * block_len; i++) {
			printf("0x%02X ", decrypted_plaintext[i]);
		}
		printf("\n\n");
	}

	if (decrypted_tag != NULL) {
		printf("decrypted_tag result : %s\n", compare(tag, decrypted_tag, 16)==0 ? "PASS" : "FAIL");
		printf("Bytes : ");
		for (int i = 0; i < 16; i++) {
			printf("0x%02X ", decrypted_tag[i]);
		}
		printf("\n");
	}
}

