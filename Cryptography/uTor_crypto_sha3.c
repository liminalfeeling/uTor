// sha3.c
// 19-Nov-11  Markku-Juhani O. Saarinen <mjos@iki.fi>
// Revised 07-Aug-15 to match with official release of FIPS PUB 202 "SHA3"
// Revised 03-Sep-15 for portability + OpenSSL - style API

#define KECCAKF_ROUNDS 24
#define ROTL64(x, y) (((x) << (y)) | ((x) >> (64 - (y))))

#include <winsock2.h>
#include "uTor_crypto_sha3.h"

VOID crypto_sha3_keccakf(UINT64 st[25]) {
	const UINT64 keccakf_rndc[24] = {
		0x0000000000000001, 0x0000000000008082, 0x800000000000808a,
		0x8000000080008000, 0x000000000000808b, 0x0000000080000001,
		0x8000000080008081, 0x8000000000008009, 0x000000000000008a,
		0x0000000000000088, 0x0000000080008009, 0x000000008000000a,
		0x000000008000808b, 0x800000000000008b, 0x8000000000008089,
		0x8000000000008003, 0x8000000000008002, 0x8000000000000080,
		0x000000000000800a, 0x800000008000000a, 0x8000000080008081,
		0x8000000000008080, 0x0000000080000001, 0x8000000080008008
	};
	const INT32 keccakf_rotc[24] = {
		1,  3,  6,  10, 15, 21, 28, 36, 45, 55, 2,  14,
		27, 41, 56, 8,  25, 43, 62, 18, 39, 61, 20, 44
	};
	const INT32 keccakf_piln[24] = {
		10, 7,  11, 17, 18, 3, 5,  16, 8,  21, 24, 4,
		15, 23, 19, 13, 12, 2, 20, 14, 22, 9,  6,  1
	};

	INT32 i, j, r;
	UINT64 t, bc[5];
	for (r = 0; r < KECCAKF_ROUNDS; r++) {
		// Theta
		for (i = 0; i < 5; i++)
			bc[i] = st[i] ^ st[i + 5] ^ st[i + 10] ^ st[i + 15] ^ st[i + 20];

		for (i = 0; i < 5; i++) {
			t = bc[(i + 4) % 5] ^ ROTL64(bc[(i + 1) % 5], 1);
			for (j = 0; j < 25; j += 5)
				st[j + i] ^= t;
		}

		// Rho Pi
		t = st[1];
		for (i = 0; i < 24; i++) {
			j = keccakf_piln[i];
			bc[0] = st[j];
			st[j] = ROTL64(t, keccakf_rotc[i]);
			t = bc[0];
		}

		//  Chi
		for (j = 0; j < 25; j += 5) {
			for (i = 0; i < 5; i++)
				bc[i] = st[j + i];
			for (i = 0; i < 5; i++)
				st[j + i] ^= (~bc[(i + 1) % 5]) & bc[(i + 2) % 5];
		}

		//  Iota
		st[0] ^= keccakf_rndc[r];
	}
}

VOID crypto_sha3_init(CRYPTO_SHA3_CTXT* c, INT32 mdlen) {
	INT32 i;
	for (i = 0; i < 25; i++)
		c->st.q[i] = 0;
	c->mdlen = mdlen;
	c->rsiz = 200 - 2 * mdlen;
	c->pt = 0;
}

VOID crypto_sha3_update(CRYPTO_SHA3_CTXT* c, const BYTE* data, SIZE_T len) {
	SIZE_T i;
	INT32 j;

	j = c->pt;
	for (i = 0; i < len; i++) {
		c->st.b[j++] ^= ((const BYTE*)data)[i];
		if (j >= c->rsiz) {
			crypto_sha3_keccakf(c->st.q);
			j = 0;
		}
	}
	c->pt = j;
}

// finalize and output a hash

VOID crypto_sha3_final(BYTE* md, CRYPTO_SHA3_CTXT* c) {
	INT32 i;

	c->st.b[c->pt] ^= 0x06;
	c->st.b[c->rsiz - 1] ^= 0x80;
	crypto_sha3_keccakf(c->st.q);

	for (i = 0; i < c->mdlen; i++) {
		((UINT8*)md)[i] = c->st.b[i];
	}
}

// SHAKE128 and SHAKE256 extensible-output functionality

VOID crypto_shake_xof(CRYPTO_SHA3_CTXT* c) {
	c->st.b[c->pt] ^= 0x1F;
	c->st.b[c->rsiz - 1] ^= 0x80;
	crypto_sha3_keccakf(c->st.q);
	c->pt = 0;
}

VOID crypto_shake_out(CRYPTO_SHA3_CTXT* c, BYTE* out, SIZE_T len) {
	SIZE_T i;
	INT32 j;

	j = c->pt;
	for (i = 0; i < len; i++) {
		if (j >= c->rsiz) {
			crypto_sha3_keccakf(c->st.q);
			j = 0;
		}
		((BYTE*)out)[i] = c->st.b[j++];
	}
	c->pt = j;
}

//hs3  * Instantiate MAC(key=k, message=m) with H(k_len | k | m), where k_len is htonll(len(k)).
VOID crypto_sha3_tor_hs3_hmac(BYTE* mac_out, BYTE* key, UINT64 key_len, BYTE* message, UINT64 message_len) {
	UINT64 key_len_be = htonll(key_len);

	CRYPTO_SHA3_CTXT ctx;
	crypto_sha3_init(&ctx, CRYPTO_SHA3_256_HASH_LEN);
	crypto_sha3_update(&ctx, &key_len_be, sizeof(UINT64));
	crypto_sha3_update(&ctx, key, key_len);
	crypto_sha3_update(&ctx, message, message_len);
	crypto_sha3_final(mac_out, &ctx);
}