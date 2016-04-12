/* $OpenBSD: poly1305.h,v 1.4 2014/05/02 03:27:54 djm Exp $ */

/* 
 * Public Domain poly1305 from Andrew Moon
 * poly1305-donna-unrolled.c from https://github.com/floodyberry/poly1305-donna
 */

#ifndef POLY1305_H
#define POLY1305_H

#include <sys/types.h>

#define POLY1305_KEYLEN		32
#define POLY1305_TAGLEN		16

void poly1305_auth(u_char out[POLY1305_TAGLEN], const u_char *m, size_t inlen,
    const u_char key[POLY1305_KEYLEN])
    __attribute__((__bounded__(__minbytes__, 1, POLY1305_TAGLEN)))
    __attribute__((__bounded__(__buffer__, 2, 3)))
    __attribute__((__bounded__(__minbytes__, 4, POLY1305_KEYLEN)));

void poly1305_rfc7539_auth(u_char out[POLY1305_TAGLEN], const u_char *m, size_t inlen,
    const u_char *aad, size_t aadlen, const u_char key[POLY1305_KEYLEN])
    __attribute__((__bounded__(__minbytes__, 1, POLY1305_TAGLEN)))
    __attribute__((__bounded__(__buffer__, 2, 3)))
    __attribute__((__bounded__(__buffer__, 4, 5)))
    __attribute__((__bounded__(__minbytes__, 6, POLY1305_KEYLEN)));

struct poly1305_ctx {
	u_char key[POLY1305_KEYLEN];

	/* precomputed multipliers */
	uint32_t r0, r1, r2, r3, r4;
	uint32_t s1, s2, s3, s4;

	/* state */
	uint32_t h0, h1, h2, h3, h4;
};

void poly1305_setup(struct poly1305_ctx *ctx, const unsigned char key[POLY1305_KEYLEN])
    __attribute__((__bounded__(__minbytes__, 2, POLY1305_KEYLEN)));

/* not-final blocks are padded with zero bytes for a 16-byte alignment */
void poly1305_update(struct poly1305_ctx *ctx, const u_char *m, size_t inlen, int final)
    __attribute__((__bounded__(__buffer__, 2, 3)));

void poly1305_finish(struct poly1305_ctx *ctx, u_char out[POLY1305_TAGLEN])
    __attribute__((__bounded__(__minbytes__, 2, POLY1305_TAGLEN)));


#endif	/* POLY1305_H */
