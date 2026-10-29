#include "test_snmp_asn1.h"

#include "../../../src/apps/snmp/snmp_asn1.h"
#include "lwip/stats.h"

#include <string.h>

#if LWIP_SNMP

static void
snmp_asn1_check_no_alloc(void)
{
  lwip_check_ensure_no_alloc(SKIP_POOL(MEMP_SYS_TIMEOUT));
}

START_TEST(test_snmp_asn1_s32_boundaries)
{
  static const struct {
    u8_t bytes[4];
    u16_t len;
    s32_t expected;
  } cases[] = {
    {{0x00}, 1, 0},
    {{0x7f}, 1, 127},
    {{0x80}, 1, -128},
    {{0xff}, 1, -1},
    {{0x00, 0x80}, 2, 128},
    {{0xff, 0x7f}, 2, -129},
    {{0x7f, 0xff}, 2, 32767},
    {{0x80, 0x00}, 2, -32768},
    {{0x00, 0x80, 0x00}, 3, 32768},
    {{0xff, 0x7f, 0xff}, 3, -32769},
    {{0x7f, 0xff, 0xff}, 3, 8388607},
    {{0x80, 0x00, 0x00}, 3, -8388608},
    {{0x00, 0x80, 0x00, 0x00}, 4, 8388608},
    {{0xff, 0x7f, 0xff, 0xff}, 4, -8388609},
    {{0x7f, 0xff, 0xff, 0xff}, 4, 2147483647},
    {{0x80, 0x00, 0x00, 0x00}, 4, (-2147483647 - 1)},
    {{0x00, 0x00, 0x00, 0x00}, 4, 0},
    {{0xff, 0xff, 0xff, 0xff}, 4, -1}
  };
  size_t i;
  LWIP_UNUSED_ARG(_i);

  for (i = 0; i < LWIP_ARRAYSIZE(cases); i++) {
    u16_t split;
    for (split = 0; split <= cases[i].len; split++) {
      u8_t bytes[5] = {0xa5, 0, 0, 0, 0};
      u16_t total = cases[i].len + 1;
      u16_t first_len = split == 0 ? total : split;
      struct snmp_pbuf_stream stream;
      s32_t value = 42;
      struct pbuf *p = pbuf_alloc(PBUF_RAW, first_len, PBUF_RAM);
      fail_unless(p != NULL);
      memcpy(&bytes[1], cases[i].bytes, cases[i].len);
      fail_unless(pbuf_take(p, bytes, first_len) == ERR_OK);
      if (first_len < total) {
        struct pbuf *tail = pbuf_alloc(PBUF_RAW, total - first_len, PBUF_RAM);
        fail_unless(tail != NULL);
        fail_unless(pbuf_take(tail, &bytes[first_len], total - first_len) == ERR_OK);
        pbuf_cat(p, tail);
      }

      fail_unless(snmp_pbuf_stream_init(&stream, p, 1, cases[i].len) == ERR_OK);
      fail_unless(snmp_asn1_dec_s32t(&stream, cases[i].len, &value) == ERR_OK);
      fail_unless(value == cases[i].expected);
      fail_unless(stream.offset == total);
      fail_unless(stream.length == 0);
      pbuf_free(p);
    }
  }
}
END_TEST

START_TEST(test_snmp_asn1_s32_invalid_length)
{
  struct snmp_pbuf_stream stream;
  struct pbuf *p = pbuf_alloc(PBUF_RAW, 5, PBUF_RAM);
  s32_t value = 42;
  LWIP_UNUSED_ARG(_i);

  fail_unless(p != NULL);
  fail_unless(snmp_pbuf_stream_init(&stream, p, 0, 5) == ERR_OK);
  fail_unless(snmp_asn1_dec_s32t(&stream, 0, &value) == ERR_VAL);
  fail_unless(stream.offset == 0);
  fail_unless(snmp_asn1_dec_s32t(&stream, 5, &value) == ERR_VAL);
  fail_unless(stream.offset == 0);
  pbuf_free(p);
}
END_TEST

START_TEST(test_snmp_asn1_s32_truncated)
{
  const u8_t bytes[] = {0x80, 0x00, 0x00, 0x00};
  u16_t len;
  LWIP_UNUSED_ARG(_i);

  for (len = 0; len < sizeof(bytes); len++) {
    struct snmp_pbuf_stream stream;
    struct pbuf *p = pbuf_alloc(PBUF_RAW, sizeof(bytes), PBUF_RAM);
    s32_t value = 42;
    fail_unless(p != NULL);
    fail_unless(pbuf_take(p, bytes, sizeof(bytes)) == ERR_OK);
    fail_unless(snmp_pbuf_stream_init(&stream, p, 0, len) == ERR_OK);
    fail_unless(snmp_asn1_dec_s32t(&stream, sizeof(bytes), &value) == ERR_BUF);

    pbuf_realloc(p, len);
    fail_unless(snmp_pbuf_stream_init(&stream, p, 0, sizeof(bytes)) == ERR_OK);
    fail_unless(snmp_asn1_dec_s32t(&stream, sizeof(bytes), &value) == ERR_BUF);
    pbuf_free(p);
  }
}
END_TEST

#endif /* LWIP_SNMP */

Suite *
snmp_asn1_suite(void)
{
#if LWIP_SNMP
  testfunc tests[] = {
    TESTFUNC(test_snmp_asn1_s32_boundaries),
    TESTFUNC(test_snmp_asn1_s32_invalid_length),
    TESTFUNC(test_snmp_asn1_s32_truncated)
  };
  return create_suite("SNMP ASN.1", tests, LWIP_ARRAYSIZE(tests),
    snmp_asn1_check_no_alloc, snmp_asn1_check_no_alloc);
#else
  return suite_create("SNMP ASN.1");
#endif
}
