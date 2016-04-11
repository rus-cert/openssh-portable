/*
 * Copyright (c) 2013 Damien Miller <djm@mindrot.org>
 *
 * Permission to use, copy, modify, and distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
 * WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
 * ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 * WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
 * ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
 * OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 */

/* $OpenBSD: cipher-chachapoly.c,v 1.7 2015/01/14 10:24:42 markus Exp $ */

#include "includes.h"

#include <sys/types.h>
#include <stdarg.h> /* needed for log.h */
#include <string.h>
#include <stdio.h>  /* needed for misc.h */

#include "log.h"
#include "sshbuf.h"
#include "ssherr.h"
#include "cipher-chachapoly.h"

int chachapoly_init(struct chachapoly_ctx *ctx,
    const u_char *key, u_int keylen)
{
	if (keylen == (32 + 32)) {
		/* chacha20-poly1305@openssh.com: 2 x 256 bit keys */
		ctx->mode = 0;
		chacha_keysetup(&ctx->main_ctx, key, 256);
		chacha_keysetup(&ctx->header_ctx, key + 32, 256);
	} else if (keylen == 32) {
		/* chacha20-poly1305: one 256 bit key */
		ctx->mode = 1;
		chacha_keysetup(&ctx->main_ctx, key, 256);
	} else {
		return SSH_ERR_INVALID_ARGUMENT;
	}
	return 0;
}

/*
 * chachapoly_crypt() operates as following:
 * En/decrypt with header key 'aadlen' bytes from 'src', storing result
 * to 'dest'. The ciphertext here is treated as additional authenticated
 * data for MAC calculation.
 * En/decrypt 'len' bytes at offset 'aadlen' from 'src' to 'dest'. Use
 * POLY1305_TAGLEN bytes at offset 'len'+'aadlen' as the authentication
 * tag. This tag is written on encryption and verified on decryption.
 */
int
chachapoly_crypt(struct chachapoly_ctx *ctx, u_int seqnr, u_char *dest,
    const u_char *src, u_int len, u_int aadlen, u_int authlen, int do_encrypt)
{
	u_char seqbuf[8];
	const u_char one[8] = { 1, 0, 0, 0, 0, 0, 0, 0 }; /* NB little-endian */
	u_char expected_tag[POLY1305_TAGLEN], poly_key[POLY1305_KEYLEN + 4];
	int r = SSH_ERR_INTERNAL_ERROR;

	/*
	 * Run ChaCha20 once to generate the Poly1305 key. The IV is the
	 * packet sequence number.
	 */
	memset(poly_key, 0, sizeof(poly_key));
	POKE_U64(seqbuf, seqnr);
	chacha_ivsetup(&ctx->main_ctx, seqbuf, NULL);
	chacha_encrypt_bytes(&ctx->main_ctx,
	    poly_key, poly_key, sizeof(poly_key));

	/* If decrypting, check tag before anything else */
	if (!do_encrypt) {
		const u_char *tag = src + aadlen + len;

		if (0 == ctx->mode) {
			poly1305_auth(expected_tag, src, aadlen + len, poly_key);
		} else {
			poly1305_rfc7539_auth(expected_tag, src + aadlen, len, src, aadlen, poly_key);
		}
		if (timingsafe_bcmp(expected_tag, tag, POLY1305_TAGLEN) != 0) {
			r = SSH_ERR_MAC_INVALID;
			goto out;
		}
	}

	/* Crypt additional data */
	if (4 != aadlen)
		goto out;

	if (0 == ctx->mode) {
		chacha_ivsetup(&ctx->header_ctx, seqbuf, NULL);
		chacha_encrypt_bytes(&ctx->header_ctx, src, dest, aadlen);
	} else {
		dest[0] = src[0] ^ poly_key[POLY1305_KEYLEN+0];
		dest[1] = src[1] ^ poly_key[POLY1305_KEYLEN+1];
		dest[2] = src[2] ^ poly_key[POLY1305_KEYLEN+2];
		dest[3] = src[3] ^ poly_key[POLY1305_KEYLEN+3];
	}

	/* Set Chacha's block counter to 1 */
	chacha_ivsetup(&ctx->main_ctx, seqbuf, one);
	chacha_encrypt_bytes(&ctx->main_ctx, src + aadlen,
	    dest + aadlen, len);

	/* If encrypting, calculate and append tag */
	if (do_encrypt) {
		if (0 == ctx->mode) {
			poly1305_auth(dest + aadlen + len, dest, aadlen + len,
			    poly_key);
		} else {
			poly1305_rfc7539_auth(dest + aadlen + len,
			    dest + aadlen, len, dest, aadlen, poly_key);
		}
	}
	r = 0;
 out:
	explicit_bzero(expected_tag, sizeof(expected_tag));
	explicit_bzero(seqbuf, sizeof(seqbuf));
	explicit_bzero(poly_key, sizeof(poly_key));
	return r;
}

/* Decrypt and extract the encrypted packet length */
int
chachapoly_get_length(struct chachapoly_ctx *ctx,
    u_int *plenp, u_int seqnr, const u_char *cp, u_int len)
{
	u_char seqbuf[8];

	if (len < 4)
		return SSH_ERR_MESSAGE_INCOMPLETE;
	POKE_U64(seqbuf, seqnr);
	if (0 == ctx->mode) {
		u_char buf[4];

		chacha_ivsetup(&ctx->header_ctx, seqbuf, NULL);
		chacha_encrypt_bytes(&ctx->header_ctx, cp, buf, 4);
		*plenp = PEEK_U32(buf);
	} else {
		u_char poly_key[POLY1305_KEYLEN + 4];

		memset(poly_key, 0, POLY1305_KEYLEN);
		memcpy(poly_key + POLY1305_KEYLEN, cp, 4);

		chacha_ivsetup(&ctx->main_ctx, seqbuf, NULL);
		chacha_encrypt_bytes(&ctx->main_ctx, poly_key, poly_key, sizeof(poly_key));
		*plenp = PEEK_U32(poly_key + POLY1305_KEYLEN);
	}
	return 0;
}
