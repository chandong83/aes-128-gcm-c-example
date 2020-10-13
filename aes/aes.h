#pragma once
/*
 * AES functions
 * Copyright (c) 2003-2006, Jouni Malinen <j@w1.fi>
 *
 * This software may be distributed under the terms of the BSD license.
 * See README for more details.
 */

#ifndef AES_H
#define AES_H

#define AES_BLOCK_SIZE 16

typedef unsigned long long u64;
typedef unsigned long u32;
//typedef unsigned long size_t;
typedef unsigned char u8;
#define NULL '\0'
/*
void* aes_encrypt_init(const u8* key, size_t len);
void aes_encrypt(void* ctx, const u8* plain, u8* crypt);
void aes_encrypt_deinit(void* ctx);
void* aes_decrypt_init(const u8* key, size_t len);
void aes_decrypt(void* ctx, const u8* crypt, u8* plain);
void aes_decrypt_deinit(void* ctx);
*/
#endif /* AES_H */