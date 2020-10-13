
/*	File: aes128e.h
 *	Synopsis: AES encryption with 128 bit key
 *	Author: yury.shukhrov@gmail.com
 *	Date: 24.11.2014
 */

 /* To save space and make the code more compact. */
typedef unsigned char byte;
/* To simplify the operation **pointer = state[4][4]. */
typedef byte Tstate[4];

/* Under the 16-byte key at k, encrypt the 16-byte plaintext at p and store it at c. */
void aes128e(unsigned char* c, const unsigned char* p, const unsigned char* k);

/* Key encryption functions. */
void sub_bytes(Tstate* state);
void shift_rows(Tstate* state);
void mix_columns(Tstate* state);
void expand_key(byte* keys, byte* key);
void key_schedule(byte* word, size_t iter);
void add_round_key(Tstate* state, byte* keys, size_t round);