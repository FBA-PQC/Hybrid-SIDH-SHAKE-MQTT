#include "masking.h"
#include <string.h>
#include <stdlib.h>
#include <stdint.h>

/* Adjust include according to your project */
#include "fips202.h"

int mask_bytes_with_seed_shake256_ex(
    const uint8_t *seed, size_t seed_len,
    const uint8_t *nonce, size_t nonce_len,
    const char *context,
    uint8_t *buf, size_t buf_len
){
    if (!seed || seed_len == 0 || !buf || buf_len == 0 || !context) {
        return 0;
    }

    size_t ctx_len = strlen(context);
    size_t in_len = seed_len + nonce_len + ctx_len;

    uint8_t *in = (uint8_t *)malloc(in_len);
    uint8_t *mask = (uint8_t *)malloc(buf_len);
    if (!in || !mask) {
        free(in);
        free(mask);
        return 0;
    }

    uint8_t *p = in;
    memcpy(p, seed, seed_len);
    p += seed_len;

    if (nonce && nonce_len > 0) {
        memcpy(p, nonce, nonce_len);
        p += nonce_len;
    }

    memcpy(p, context, ctx_len);

    /* SHAKE256(output, outlen, input, inlen) */
    shake256(mask, buf_len, in, in_len);

    for (size_t i = 0; i < buf_len; i++) {
        buf[i] ^= mask[i];
    }

    /* Clean sensitive temp buffers */
    memset(mask, 0, buf_len);
    memset(in, 0, in_len);

    free(mask);
    free(in);
    return 1;
}