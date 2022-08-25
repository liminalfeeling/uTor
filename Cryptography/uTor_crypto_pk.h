#pragma once
#define WIN32_LEAN_AND_MEAN
#include <Windows.h>
#include <bcrypt.h>
#include "../Platform/uTor_memory.h"

#define CRYPTO_ECC25519_KEY_LEN 32

typedef struct {
	BYTE data[CRYPTO_ECC25519_KEY_LEN];
} CRYPTO_ECC25519_KEY, CRYPTO_ED25519_KEY, CRYPTO_ECC25519_IDENT;

typedef struct {
	UINT32 magic;
	UINT32 keylen;
	CRYPTO_ECC25519_KEY public_key; //pub
	CRYPTO_ECC25519_KEY unknown; //pub
	CRYPTO_ECC25519_KEY private_key; //priv
} CRYPTO_ECC25519_BLOB;

BOOL crypto_pk_init();
BOOL crypto_ed25519_derive_shared_secret(BYTE* secret_out, BCRYPT_KEY_HANDLE pubkey, BCRYPT_KEY_HANDLE privkey);
BCRYPT_KEY_HANDLE crypto_ecc25519_import_pubkey(BYTE* pubkey);
BCRYPT_KEY_HANDLE crypto_ecc25519_gen_keypair();