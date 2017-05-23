/* -*- Mode: C; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */
/*
 * libdukpt - Credit card data encryption and decryption with DUKPT
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2.1 of the License, or (at your option) any later version.
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, write to the
 * Free Software Foundation, Inc., 51 Franklin Street, Fifth Floor,
 * Boston, MA 02110-1301 USA.
 *
 * Copyright (C) 2017 Zodiac Inflight Innovations
 * Copyright (C) 2017 Aleksander Morgado <aleksander@aleksander.es>
 *
 * Thanks to IDTECH products for the detailed explanations:
 *   http://www.idtechproducts.com/blog/entry/how-to-decrypt-credit-card-data-part-i
 *   http://www.idtechproducts.com/blog/entry/how-to-decrypt-credit-card-data-part-ii
 */

#include <malloc.h>
#include <string.h>
#include <inttypes.h>
#include <stdint.h>
#include <stdbool.h>
#include <assert.h>

#include <openssl/des.h>

#include "dukpt.h"

/* Define DUKPT_DEBUG to get a verbose printing of the different steps in the
 * operations */
#if defined DUKPT_DEBUG

static char *
strhex (const void *mem,
        size_t      size,
        const char *delimiter)
{
    const uint8_t *data = mem;
    size_t         i, j, new_str_length, delimiter_length;
    char          *new_str;

    assert (size > 0);

    /* Allow delimiters of arbitrary sizes, including 0 */
    delimiter_length = (delimiter ? strlen (delimiter) : 0);

    /* Get new string length. If input string has N bytes, we need:
     * - 1 byte for last NUL char
     * - 2N bytes for hexadecimal char representation of each byte...
     * - N-1 times the delimiter length
     * So... e.g. if delimiter is 1 byte,  a total of:
     *   (1+2N+N-1) = 3N bytes are needed...
     */
    new_str_length =  1 + (2 * size) + ((size - 1) * delimiter_length);

    /* Allocate memory for new array and initialize contents to NUL */
    new_str = calloc (new_str_length, 1);

    /* Print hexadecimal representation of each byte... */
    for (i = 0, j = 0; i < size; i++, j += (2 + delimiter_length)) {
        /* Print character in output string... */
        snprintf (&new_str[j], 3, "%02X", data[i]);
        /* And if needed, add separator */
        if (delimiter_length && i != (size - 1) )
            strncpy (&new_str[j + 2], delimiter, delimiter_length);
    }

    /* Set output string */
    return new_str;
}

#define trace(message, ...) printf (message "\n", ##__VA_ARGS__)

static void
trace_array (const char    *array_desc,
             const uint8_t *array,
             size_t         array_size)
{
    char *hex;

    hex = strhex (array, array_size, ":");
    trace ("%s (%zu bytes): %s", array_desc, array_size, hex);
    free (hex);
}

#else
#define trace(...)
#define trace_array(...)
#endif

/******************************************************************************/
/* Private useful types */

/* A block is an 8-byte array, i.e. half a dukpt_key_t.
 * We are also able to cast it to DES_cblock when needed. */
#define BLOCK_SIZE 8
typedef uint8_t block_t [BLOCK_SIZE];

/* The counter is a 3-byte array */
#define COUNTER_SIZE 3
typedef uint8_t counter_t [COUNTER_SIZE];

static const dukpt_key_t c0c0_mask = {
    0xc0, 0xc0, 0xc0, 0xc0, 0x00, 0x00, 0x00, 0x00,
    0xc0, 0xc0, 0xc0, 0xc0, 0x00, 0x00, 0x00, 0x00
};

static void
array_xor (size_t         size,
           const uint8_t *a,
           const uint8_t *b,
           uint8_t       *out)
{
    size_t i;

    for (i = 0; i < size; i++)
        out[i] = a[i] ^ b[i];
}

typedef enum {
    TDES_OPERATION_TYPE_DECRYPT = 0,
    TDES_OPERATION_TYPE_ENCRYPT = 1,
} tdes_operation_type_t;

#if defined DUKPT_DEBUG

static const char *tdes_operation_type_str[] = {
    [TDES_OPERATION_TYPE_DECRYPT] = "decrypt",
    [TDES_OPERATION_TYPE_ENCRYPT] = "encrypt",
};

#endif

static void
tdes_encrypt (tdes_operation_type_t  op,
              const uint8_t         *data,
              size_t                 data_size,
              const uint8_t         *key,
              size_t                 key_size,
              uint8_t               *out,
              size_t                 out_size)
{
    DES_key_schedule ks1, ks2, ks3;
    DES_cblock       k1, k2, k3;
	DES_cblock       iv = { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 };
    int              enc;

    assert (out_size >= data_size);

    trace ("[tdes %s] new operation", tdes_operation_type_str[op]);
    trace_array ("input data", data, data_size);

    memcpy (k1, &key[0], sizeof (k1));
    memcpy (k2, &key[8], sizeof (k2));

    /* If the key is 16 bits, reuse the first 8 bits (EDE3 method) */
    if (key_size == 24)
        memcpy (k3, &key[16], sizeof (k3));
    else if (key_size == 16)
        memcpy (k3, &key[0], sizeof (k3));
    else
        assert (0);

    if (op == TDES_OPERATION_TYPE_ENCRYPT)
        enc = DES_ENCRYPT;
    else if (op == TDES_OPERATION_TYPE_DECRYPT)
        enc = DES_DECRYPT;
    else
        assert (0);

    trace_array ("key 1", k1, sizeof (k1));
    trace_array ("key 2", k2, sizeof (k2));
    trace_array ("key 3", k3, sizeof (k3));

    /* Triple-DES CBC Encryption */
    DES_set_key_unchecked (&k1, &ks1);
    DES_set_key_unchecked (&k2, &ks2);
    DES_set_key_unchecked (&k3, &ks3);

    DES_ede3_cbc_encrypt ((unsigned char *) data, (unsigned char *) out, data_size, &ks1, &ks2, &ks3, &iv, enc);
    trace_array ("output", out, data_size);
}

void
dukpt_compute_ipek (const dukpt_key_t *bdk,
                    const dukpt_ksn_t *ksn,
                    dukpt_key_t       *out_ipek)
{
    block_t     base_ksn;
    dukpt_key_t bdk_xor_c0c0;

    trace ("----------------------------");
    trace ("[compute ipek] new operation");

    trace_array ("[compute ipek] ksn", *ksn, DUKPT_KSN_SIZE);
    trace_array ("[compute ipek] bdk", *bdk, DUKPT_KEY_SIZE);

    /* Build base ksn.
     *
     * We copy the first 8 bytes of the ksn, but we fix the last byte so that
     * all bits that apply to the counter are set to 0. Counter is 21 bits, so
     * the 5 least significant bits of the 3rd byte of the counter are the ones
     * to clear.
     */
    memcpy (base_ksn, *ksn, BLOCK_SIZE);
    base_ksn [BLOCK_SIZE - 1] &= 0b11100000;
    trace_array ("[compute base ksn] base ksn", base_ksn, BLOCK_SIZE);

    /* left half of the ipek (most significant 8 bytes) */
    tdes_encrypt (TDES_OPERATION_TYPE_ENCRYPT,
                  base_ksn,  BLOCK_SIZE,
                  *bdk,      DUKPT_KEY_SIZE,
                  *out_ipek, BLOCK_SIZE);

    array_xor (DUKPT_KEY_SIZE, *bdk, c0c0_mask, bdk_xor_c0c0);
    trace_array ("[compute ipek] bdk xor c0c0", bdk_xor_c0c0, DUKPT_KEY_SIZE);

    /* right half of the ipek (least significant 8 bytes) */
    tdes_encrypt (TDES_OPERATION_TYPE_ENCRYPT,
                  base_ksn,                 BLOCK_SIZE,
                  bdk_xor_c0c0,             DUKPT_KEY_SIZE,
                  &(*out_ipek)[BLOCK_SIZE], BLOCK_SIZE);

    trace_array ("[compute ipek] computed ipek", *out_ipek, DUKPT_KEY_SIZE);
}

static void
encrypt_register (const block_t     *base_ksn,
                  const dukpt_key_t *key,
                  block_t           *out)
{
    DES_key_schedule ks;
    block_t          base_ksn_xor_bottom, bottom, top, des_output;

    trace ("[encrypt register] new operation");

    memcpy (top, *key, BLOCK_SIZE);
    trace_array ("[encrypt register]   top (key):", top, BLOCK_SIZE);

    memcpy (bottom, &(*key)[BLOCK_SIZE], BLOCK_SIZE);
    trace_array ("[encrypt register]   bottom", bottom, BLOCK_SIZE);
    array_xor (BLOCK_SIZE, *base_ksn, bottom, base_ksn_xor_bottom);
    trace_array ("[encrypt register]   base ksn xor bottom (data)", base_ksn_xor_bottom, BLOCK_SIZE);

    /* Single-DES Encryption */
    DES_set_key_unchecked ((DES_cblock *) &top, &ks);
    DES_ecb_encrypt ((DES_cblock *) &base_ksn_xor_bottom, (DES_cblock *) &des_output, &ks, DES_ENCRYPT);
    trace_array ("[encrypt register]   des output", des_output, BLOCK_SIZE);

    array_xor (BLOCK_SIZE, des_output, bottom, *out);
    trace_array ("[encrypt register]   des output xor bottom (output)", *out, BLOCK_SIZE);
}

static void
generate_key (const dukpt_key_t *cur,
              const block_t     *base_ksn,
              dukpt_key_t       *out)
{
    dukpt_key_t cur_xor_c0c0;
    block_t     top, bottom;

    /* generate bottom half of the key (least significant 8 bytes) */
    encrypt_register (base_ksn, cur, &bottom);
    trace_array ("[generate key] bottom", bottom, BLOCK_SIZE);

    array_xor (DUKPT_KEY_SIZE, *cur, c0c0_mask, cur_xor_c0c0);
    trace_array ("[generate key] cur xor c0c0", cur_xor_c0c0, DUKPT_KEY_SIZE);

    /* generate top half of the key (most significant 8 bytes) */
    encrypt_register (base_ksn, (const dukpt_key_t *) &cur_xor_c0c0, &top);
    trace_array ("[generate key] top", top, BLOCK_SIZE);

    /* set output key by joining top and bottom, but don't do this directly in
     * each step above, as the output buffer may actually be the input one as
     * well */
    memcpy (*out, top, BLOCK_SIZE);
    memcpy (&(*out)[BLOCK_SIZE], bottom, BLOCK_SIZE);
}

static void
compute_derived_key (const dukpt_key_t *ipek,
                     const dukpt_ksn_t *ksn,
                     dukpt_key_t       *out_key)
{
    dukpt_key_t cur_key;
    block_t     base_ksn = { 0 };
    counter_t   counter;
    int         byte_i = 0;
    int         bit_shift = 4;

    trace ("----------------------------");
    trace ("[compute derived key] new operation");

    /* Build base ksn.
     *
     * We need to copy the last 8 bytes of the ksn, and then AND the resulting
     * array with 0xFFFFFFFFFFE00000. This is the same as copying only 6 of the
     * bytes and fixing the last one copied.
     */
    memcpy (base_ksn, &(*ksn)[DUKPT_KSN_SIZE - BLOCK_SIZE], BLOCK_SIZE - 2);
    base_ksn [BLOCK_SIZE - 3] &= 0xe0;
    trace_array ("[compute derived key] base ksn", base_ksn, BLOCK_SIZE);

    /* Build counter.
     *
     * We copy the last 3 bytes of the ksn, but we fix the most significant byte
     * so that all bits that don't apply to the counter are set to 0. Counter is
     * 21 bits.
     */
    memcpy (counter, &(*ksn)[DUKPT_KSN_SIZE - COUNTER_SIZE], COUNTER_SIZE);
    counter [0] &= 0x1f;
    trace_array ("[compute derived key] counter", counter, COUNTER_SIZE);

    /* Initialize current key */
    memcpy (cur_key, *ipek, DUKPT_KEY_SIZE);
    trace_array ("[compute derived key] current key", cur_key, DUKPT_KEY_SIZE);

    /* Iterate counter, starting at 0x100000: byte 0, bit 5 (1 << 4) */
    for (byte_i = 0, bit_shift = 4; byte_i < COUNTER_SIZE; byte_i++, bit_shift = 7) {
        for (; bit_shift >= 0; bit_shift--) {
#if defined DUKPT_DEBUG
            {
                counter_t counter_iter = { 0x00, 0x00, 0x00 };

                counter_iter[byte_i] |= (1 << bit_shift);
                trace_array ("[compute derived key] counter iteration", counter_iter, COUNTER_SIZE);
            }
#endif

            /* If the counter has the bit set, we set the same bit in the base ksn,
             * and update the current key */
            if (counter[byte_i] & (1 << bit_shift)) {
                base_ksn[BLOCK_SIZE - COUNTER_SIZE + byte_i] |= (1 << bit_shift);
                trace_array ("[compute derived key] updated base ksn", base_ksn, BLOCK_SIZE);
                generate_key ((const dukpt_key_t *) &cur_key, (const block_t *) &base_ksn, &cur_key);
                trace_array ("[compute derived key] updated current key", cur_key, DUKPT_KEY_SIZE);
            }
        }
    }

    memcpy (*out_key, cur_key, DUKPT_KEY_SIZE);
    trace_array ("[compute derived key] derived key", *out_key, DUKPT_KEY_SIZE);
}

void
dukpt_compute_key (const dukpt_key_t *ipek,
                   const dukpt_ksn_t *ksn,
                   dukpt_key_type_t   type,
                   dukpt_key_t       *out_key)
{
    static const dukpt_key_t pin_encryption_mask = {
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xff,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xff
    };
    static const dukpt_key_t mac_request_mask = {
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xff, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xff, 0x00
    };
    static const dukpt_key_t mac_response_mask = {
        0x00, 0x00, 0x00, 0x00, 0xff, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0xff, 0x00, 0x00, 0x00
    };
    static const dukpt_key_t data_request_mask = {
        0x00, 0x00, 0x00, 0x00, 0x00, 0xff, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0xff, 0x00, 0x00
    };
    static const dukpt_key_t data_response_mask = {
        0x00, 0x00, 0x00, 0xff, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0xff, 0x00, 0x00, 0x00, 0x00
    };
    dukpt_key_t derived_key, tmp_key;

    compute_derived_key (ipek, ksn, &derived_key);

    switch (type) {
    case DUKPT_KEY_TYPE_DERIVED:
        memcpy (*out_key, derived_key, DUKPT_KEY_SIZE);
        return;
    case DUKPT_KEY_TYPE_PIN_ENCRYPTION:
        array_xor (DUKPT_KEY_SIZE, derived_key, pin_encryption_mask, *out_key);
        return;
    case DUKPT_KEY_TYPE_MAC_REQUEST:
        array_xor (DUKPT_KEY_SIZE, derived_key, mac_request_mask, *out_key);
        return;
    case DUKPT_KEY_TYPE_MAC_RESPONSE:
        array_xor (DUKPT_KEY_SIZE, derived_key, mac_response_mask, *out_key);
        return;
    case DUKPT_KEY_TYPE_DATA_REQUEST:
        array_xor (DUKPT_KEY_SIZE, derived_key, data_request_mask, tmp_key);
        break;
    case DUKPT_KEY_TYPE_DATA_RESPONSE:
        array_xor (DUKPT_KEY_SIZE, derived_key, data_response_mask, tmp_key);
        break;
    default:
        assert (0);
    }

    tdes_encrypt (TDES_OPERATION_TYPE_ENCRYPT,
                  tmp_key,  BLOCK_SIZE,
                  tmp_key,  DUKPT_KEY_SIZE,
                  *out_key, BLOCK_SIZE);
    tdes_encrypt (TDES_OPERATION_TYPE_ENCRYPT,
                  &tmp_key[BLOCK_SIZE],    BLOCK_SIZE,
                  tmp_key,                 DUKPT_KEY_SIZE,
                  &(*out_key)[BLOCK_SIZE], BLOCK_SIZE);
}

void
dukpt_encrypt (const dukpt_key_t *key,
               const uint8_t     *data,
               size_t             data_size,
               uint8_t           *out,
               size_t             out_size)
{
    tdes_encrypt (TDES_OPERATION_TYPE_ENCRYPT,
                  data,                   data_size,
                  (const uint8_t *) key,  DUKPT_KEY_SIZE,
                  out,                    out_size);
}

void
dukpt_decrypt (const dukpt_key_t *key,
               const uint8_t     *data,
               size_t             data_size,
               uint8_t           *out,
               size_t             out_size)
{
    tdes_encrypt (TDES_OPERATION_TYPE_DECRYPT,
                  data,                   data_size,
                  (const uint8_t *) key,  DUKPT_KEY_SIZE,
                  out,                    out_size);
}

/******************************************************************************/
/* Library version info */

unsigned int
dukpt_get_major_version (void)
{
    return DUKPT_MAJOR_VERSION;
}

unsigned int
dukpt_get_minor_version (void)
{
    return DUKPT_MINOR_VERSION;
}

unsigned int
dukpt_get_micro_version (void)
{
    return DUKPT_MICRO_VERSION;
}
