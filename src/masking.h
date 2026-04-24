#ifndef MASKING_H
#define MASKING_H

#include <stddef.h>
#include <stdint.h>

/*
 * XOR-mask/unmask buffer in place using:
 *   SHAKE256(seed || nonce || context)
 *
 * Returns 1 on success, 0 on failure.
 */
int mask_bytes_with_seed_shake256_ex(
    const uint8_t *seed, size_t seed_len,
    const uint8_t *nonce, size_t nonce_len,
    const char *context,
    uint8_t *buf, size_t buf_len
);

#endif