/* -*- Mode: C; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */
/*
 * Copyright (C) 2017 Zodiac Inflight Innovations
 * All rights reserved.
 *
 * Author: Aleksander Morgado <aleksander@aleksander.es>
 */

#include <stdio.h>
#include <stdlib.h>
#include <assert.h>
#include <check.h>

#include <dukpt.h>

/******************************************************************************/

START_TEST (test_ipek)
{
    static const dukpt_ksn_t ksn = {
        0x62, 0x99, 0x49, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x01
    };
    static const dukpt_key_t bdk = {
        0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef,
        0xfe, 0xdc, 0xba, 0x98, 0x76, 0x54, 0x32, 0x10
    };
    static const dukpt_key_t expected_ipek = {
        0xb5, 0x61, 0x06, 0x50, 0xeb, 0xc2, 0x4c, 0xa3,
        0xca, 0xcd, 0xd0, 0x8d, 0xda, 0xfe, 0x8c, 0xe3
    };
    dukpt_key_t ipek;

    dukpt_compute_ipek (&bdk, &ksn, &ipek);
    ck_assert (memcmp (ipek, expected_ipek, DUKPT_KEY_SIZE) == 0);
}
END_TEST

START_TEST (test_ipek_2)
{
    static const dukpt_ksn_t ksn = {
        0x62, 0x99, 0x49, 0x01, 0x2c,
        0x00, 0x00, 0x00, 0x00, 0x03
    };
    static const dukpt_key_t bdk = {
        0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef,
        0xfe, 0xdc, 0xba, 0x98, 0x76, 0x54, 0x32, 0x10
    };
    static const dukpt_key_t expected_ipek = {
        0xd2, 0x94, 0x3c, 0xcf, 0x80, 0xf4, 0x2e, 0x88,
        0xe2, 0x3c, 0x12, 0xd1, 0x16, 0x2f, 0xd5, 0x47
    };
    dukpt_key_t ipek;

    dukpt_compute_ipek (&bdk, &ksn, &ipek);
    ck_assert (memcmp (ipek, expected_ipek, DUKPT_KEY_SIZE) == 0);
}
END_TEST

START_TEST (test_derived_key)
{
    static const dukpt_ksn_t ksn = {
        0x62, 0x99, 0x49, 0x01, 0x2c,
        0x00, 0x00, 0x00, 0x00, 0x03
    };
    static const dukpt_key_t ipek = {
        0xd2, 0x94, 0x3c, 0xcf, 0x80, 0xf4, 0x2e, 0x88,
        0xe2, 0x3c, 0x12, 0xd1, 0x16, 0x2f, 0xd5, 0x47
    };
    static const dukpt_key_t expected_key = {
        0x84, 0x1a, 0xb7, 0xb9, 0x4e, 0xd0, 0x86, 0xeb,
        0xc2, 0xb8, 0xa8, 0x38, 0x5d, 0xa7, 0xdf, 0xca
    };
    dukpt_key_t key;

    dukpt_compute_key (&ipek, &ksn, DUKPT_KEY_TYPE_DERIVED, &key);
    ck_assert (memcmp (key, expected_key, DUKPT_KEY_SIZE) == 0);
}
END_TEST

START_TEST (test_pin_encryption_key)
{
    static const dukpt_ksn_t ksn = {
        0x62, 0x99, 0x49, 0x01, 0x2c,
        0x00, 0x00, 0x00, 0x00, 0x03
    };
    static const dukpt_key_t ipek = {
        0xd2, 0x94, 0x3c, 0xcf, 0x80, 0xf4, 0x2e, 0x88,
        0xe2, 0x3c, 0x12, 0xd1, 0x16, 0x2f, 0xd5, 0x47
    };
    static const dukpt_key_t expected_key = {
        0x84, 0x1a, 0xb7, 0xb9, 0x4e, 0xd0, 0x86, 0x14,
        0xc2, 0xb8, 0xa8, 0x38, 0x5d, 0xa7, 0xdf, 0x35
    };
    dukpt_key_t key;

    dukpt_compute_key (&ipek, &ksn, DUKPT_KEY_TYPE_PIN_ENCRYPTION, &key);
    ck_assert (memcmp (key, expected_key, DUKPT_KEY_SIZE) == 0);
}
END_TEST

START_TEST (test_mac_request_key)
{
    static const dukpt_ksn_t ksn = {
        0x62, 0x99, 0x49, 0x01, 0x2c,
        0x00, 0x00, 0x00, 0x00, 0x03
    };
    static const dukpt_key_t ipek = {
        0xd2, 0x94, 0x3c, 0xcf, 0x80, 0xf4, 0x2e, 0x88,
        0xe2, 0x3c, 0x12, 0xd1, 0x16, 0x2f, 0xd5, 0x47
    };
    static const dukpt_key_t expected_key = {
        0x84, 0x1a, 0xb7, 0xb9, 0x4e, 0xd0, 0x79, 0xeb,
        0xc2, 0xb8, 0xa8, 0x38, 0x5d, 0xa7, 0x20, 0xca
    };
    dukpt_key_t key;

    dukpt_compute_key (&ipek, &ksn, DUKPT_KEY_TYPE_MAC_REQUEST, &key);
    ck_assert (memcmp (key, expected_key, DUKPT_KEY_SIZE) == 0);
}
END_TEST

START_TEST (test_data_request_key)
{
    static const dukpt_ksn_t ksn = {
        0x62, 0x99, 0x49, 0x01, 0x2c,
        0x00, 0x00, 0x00, 0x00, 0x03
    };
    static const dukpt_key_t ipek = {
        0xd2, 0x94, 0x3c, 0xcf, 0x80, 0xf4, 0x2e, 0x88,
        0xe2, 0x3c, 0x12, 0xd1, 0x16, 0x2f, 0xd5, 0x47
    };
    static const dukpt_key_t expected_key = {
        0xf7, 0x39, 0xae, 0xf5, 0x95, 0xd3, 0x87, 0x7f,
        0x73, 0x17, 0x82, 0xd2, 0x8b, 0xb6, 0xac, 0x4f
    };
    dukpt_key_t key;

    dukpt_compute_key (&ipek, &ksn, DUKPT_KEY_TYPE_DATA_REQUEST, &key);
    ck_assert (memcmp (key, expected_key, DUKPT_KEY_SIZE) == 0);
}
END_TEST

START_TEST (test_encrypt_decrypt)
{
    static const dukpt_ksn_t ksn = {
        0x62, 0x99, 0x49, 0x01, 0x2c,
        0x00, 0x00, 0x00, 0x00, 0x03
    };
    static const dukpt_key_t ipek = {
        0xd2, 0x94, 0x3c, 0xcf, 0x80, 0xf4, 0x2e, 0x88,
        0xe2, 0x3c, 0x12, 0xd1, 0x16, 0x2f, 0xd5, 0x47
    };
    static const char *input_texts[] = {
        "Lorem ipsum dolor sit amet, consectetur adipiscing elit.",
        "short",
        "vs"
    };

    unsigned int i;

    for (i = 0; i < (sizeof (input_texts) / sizeof (input_texts[0])); i++) {
        dukpt_key_type_t key_type;
        size_t           data_size;
        char             encrypted_text[256];
        char             decrypted_text[256];

        data_size = strlen (input_texts[i]);
        assert (data_size <= sizeof (encrypted_text));

        for (key_type = DUKPT_KEY_TYPE_PIN_ENCRYPTION; key_type <= DUKPT_KEY_TYPE_DATA_RESPONSE; key_type++) {
            dukpt_key_t key;

            memset (encrypted_text, 0, sizeof (encrypted_text));
            memset (decrypted_text, 0, sizeof (decrypted_text));

            dukpt_compute_key (&ipek, &ksn, key_type, &key);
            dukpt_encrypt (&key, (const uint8_t *) input_texts[i], data_size, (uint8_t *) encrypted_text, data_size);
            dukpt_decrypt (&key, (const uint8_t *) encrypted_text, data_size, (uint8_t *) decrypted_text, data_size);

            ck_assert (memcmp (decrypted_text, input_texts[i], data_size) == 0);
        }
    }
}
END_TEST

int main (int argc, char **argv)
{
    Suite   *s;
    TCase   *tc;
    SRunner *sr;
    int      failed;

    s = suite_create ("DUKPT tests");

    tc = tcase_create ("ipek");
    tcase_add_test (tc, test_ipek);
    tcase_add_test (tc, test_ipek_2);
    suite_add_tcase (s, tc);

    tc = tcase_create ("derived");
    tcase_add_test (tc, test_derived_key);
    suite_add_tcase (s, tc);

    tc = tcase_create ("pin encryption");
    tcase_add_test (tc, test_pin_encryption_key);
    suite_add_tcase (s, tc);

    tc = tcase_create ("mac request");
    tcase_add_test (tc, test_mac_request_key);
    suite_add_tcase (s, tc);

    tc = tcase_create ("data request");
    tcase_add_test (tc, test_data_request_key);
    suite_add_tcase (s, tc);

    tc = tcase_create ("encrypt decrypt");
    tcase_add_test (tc, test_encrypt_decrypt);
    suite_add_tcase (s, tc);

    sr = srunner_create (s);
    srunner_run_all (sr, CK_VERBOSE);
    failed = srunner_ntests_failed (sr);
    srunner_free (sr);

    return failed == 0 ? EXIT_SUCCESS : EXIT_FAILURE;
}
