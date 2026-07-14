/* crypto.c - LMDB encryption helper module */
/*
 * Copyright 2020-2024 Howard Chu, Symas Corp.
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted only as authorized by the OpenLDAP
 * Public License.
 *
 * A copy of this license is available in the file LICENSE in the
 * source distribution.
 */
#include <string.h>

#include <sodium.h>

#include "lmdb.h"

#define KEYBYTES	crypto_aead_chacha20poly1305_ietf_KEYBYTES
#define NONCEBYTES	crypto_aead_chacha20poly1305_ietf_NPUBBYTES
#define MACBYTES	crypto_aead_chacha20poly1305_ietf_ABYTES
#define SUMBYTES	crypto_hash_sha256_BYTES

MDB_crypto_hooks MDB_crypto;

static int mcf_str2key(const char *passwd, MDB_val *key)
{
	crypto_hash_sha256_state state;

	crypto_hash_sha256_init(&state);
	crypto_hash_sha256_update(&state, (const unsigned char *)"Just a Constant", sizeof("Just a Constant"));
	crypto_hash_sha256_update(&state, (const unsigned char *)passwd, strlen(passwd));
	crypto_hash_sha256_final(&state, key->mv_data);
	return 0;
}

static void mcf_sumfunc(const MDB_val *src, MDB_val *dst, const MDB_val *key)
{
	crypto_hash_sha256_state state;

	crypto_hash_sha256_init(&state);
	if (key)
		crypto_hash_sha256_update(&state, (const unsigned char *)key->mv_data, key->mv_size);
	crypto_hash_sha256_update(&state, (const unsigned char *)src->mv_data, src->mv_size);
	crypto_hash_sha256_final(&state, dst->mv_data);
}

#define ENC(dst, src, mac, key, iv) \
	crypto_aead_chacha20poly1305_ietf_encrypt_detached(dst->mv_data, mac, &mlen, \
		src->mv_data, src->mv_size, NULL, 0, NULL, iv, key)

#define DEC(dst, src, mac, key, iv) \
	crypto_aead_chacha20poly1305_ietf_decrypt_detached(dst->mv_data, NULL, src->mv_data, \
		src->mv_size, mac, NULL, 0, iv, key)

static int mcf_encfunc(const MDB_val *src, MDB_val *dst, const MDB_val *key, int encdec)
{
	unsigned char iv[NONCEBYTES];
	mdb_size_t *ptr;
	int ivl, rc;
	unsigned long long mlen;

	/* the nonce is only 12 bytes */
	ptr = key[1].mv_data;
	ivl = ptr[0] & 0xffffffff;
	memcpy(iv, &ivl, 4);
	memcpy(iv+4, ptr+1, sizeof(mdb_size_t));

	if (encdec) {
		rc = ENC(dst, src, key[2].mv_data, key[0].mv_data, iv);
	} else {
		if (key[2].mv_size)
			rc = DEC(dst, src, key[2].mv_data, key[0].mv_data, iv);
		else {
			/* Decrypting without MAC check: only used when decrypting page
			 * headers during incremental load.
			 */
			rc = crypto_stream_chacha20_ietf_xor_ic(dst->mv_data, src->mv_data,
				src->mv_size, iv, 1, key[0].mv_data);
		}
	}
	return rc;
}

static const MDB_crypto_funcs mcf_table = {
	mcf_str2key,
	mcf_encfunc,
	mcf_sumfunc,
	KEYBYTES,
	MACBYTES,
	SUMBYTES
};

MDB_crypto_funcs *MDB_crypto()
{
	return (MDB_crypto_funcs *)&mcf_table;
}
