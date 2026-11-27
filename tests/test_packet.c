#include "packet.h"

#include <stdio.h>
#include <string.h>

static int failures = 0;
static int checks = 0;

#define CHECK(cond)                                                            \
  do {                                                                         \
    checks++;                                                                  \
    if (!(cond)) {                                                             \
      failures++;                                                              \
      fprintf(stderr, "%s:%d: CHECK failed: %s\n", __FILE__, __LINE__, #cond); \
    }                                                                          \
  } while (0)

#define ETH_LEN 14u
#define IP_LEN 20u
#define MAX_TEST_FRAME 256u

static void put_be16(uint8_t *p, uint16_t v) {
  p[0] = (uint8_t)(v >> 8);
  p[1] = (uint8_t)(v & 0xFFu);
}

static void fix_ipv4_checksum(uint8_t *ip) {
  uint32_t sum = 0;
  put_be16(ip + 10, 0);
  for (size_t i = 0; i < IP_LEN; i += 2) {
    sum += (uint32_t)((ip[i] << 8) | ip[i + 1]);
  }
  while (sum >> 16) {
    sum = (sum & 0xFFFFu) + (sum >> 16);
  }
  put_be16(ip + 10, (uint16_t)~sum);
}

/* Builds Ethernet + IPv4 (192.168.1.10 -> 10.0.0.1) carrying the given L4
 * bytes. */
static size_t build_ipv4_frame(uint8_t *buf, uint8_t proto, const uint8_t *l4,
                               size_t l4_len) {
  memset(buf, 0, MAX_TEST_FRAME);
  memset(buf, 0x02, 6);     /* dst MAC */
  memset(buf + 6, 0x04, 6); /* src MAC */
  put_be16(buf + 12, 0x0800);

  uint8_t *ip = buf + ETH_LEN;
  ip[0] = 0x45; /* IPv4, IHL=5 */
  put_be16(ip + 2, (uint16_t)(IP_LEN + l4_len));
  ip[8] = 64;
  ip[9] = proto;
  ip[12] = 192;
  ip[13] = 168;
  ip[14] = 1;
  ip[15] = 10;
  ip[16] = 10;
  ip[17] = 0;
  ip[18] = 0;
  ip[19] = 1;
  fix_ipv4_checksum(ip);

  memcpy(ip + IP_LEN, l4, l4_len);
  return ETH_LEN + IP_LEN + l4_len;
}

static size_t build_tcp_frame(uint8_t *buf) {
  uint8_t tcp[25] = {0};
  put_be16(tcp, 51234);         /* src port */
  put_be16(tcp + 2, 443);       /* dst port */
  tcp[12] = 0x50;               /* data offset = 5 words */
  memcpy(tcp + 20, "hello", 5); /* payload */
  return build_ipv4_frame(buf, NP_IP_PROTO_TCP, tcp, sizeof(tcp));
}

static size_t build_udp_frame(uint8_t *buf) {
  uint8_t udp[18] = {0};
  put_be16(udp, 40000);
  put_be16(udp + 2, 53);
  put_be16(udp + 4, sizeof(udp));
  memcpy(udp + 8, "0123456789", 10);
  return build_ipv4_frame(buf, NP_IP_PROTO_UDP, udp, sizeof(udp));
}

static void test_tcp_frame(void) {
  uint8_t frame[MAX_TEST_FRAME];
  size_t len = build_tcp_frame(frame);
  np_packet_info info;

  CHECK(np_parse_ethernet_frame(frame, len, &info) == NP_OK);
  CHECK(info.ip_protocol == NP_IP_PROTO_TCP);
  CHECK(info.ip_checksum_ok == 1);
  CHECK(info.src_port == 51234);
  CHECK(info.dst_port == 443);
  CHECK(info.payload_length == 5);
  CHECK(memcmp(info.src_ip, "\xC0\xA8\x01\x0A", 4) == 0);
  CHECK(memcmp(info.dst_ip, "\x0A\x00\x00\x01", 4) == 0);
  CHECK(info.src_mac[0] == 0x04);
  CHECK(info.dst_mac[0] == 0x02);
}

static void test_udp_frame(void) {
  uint8_t frame[MAX_TEST_FRAME];
  size_t len = build_udp_frame(frame);
  np_packet_info info;

  CHECK(np_parse_ethernet_frame(frame, len, &info) == NP_OK);
  CHECK(info.ip_protocol == NP_IP_PROTO_UDP);
  CHECK(info.src_port == 40000);
  CHECK(info.dst_port == 53);
  CHECK(info.payload_length == 10);
}

static void test_bad_ip_checksum_is_reported(void) {
  uint8_t frame[MAX_TEST_FRAME];
  size_t len = build_tcp_frame(frame);
  frame[ETH_LEN + 8] ^= 0xFF; /* corrupt TTL without fixing checksum */

  np_packet_info info;
  CHECK(np_parse_ethernet_frame(frame, len, &info) == NP_OK);
  CHECK(info.ip_checksum_ok == 0);
}

static void test_truncated_l4_is_rejected(void) {
  uint8_t frame[MAX_TEST_FRAME];
  build_tcp_frame(frame);

  np_packet_info info;
  /* Capture cuts the TCP header short (10 of 20 bytes). */
  CHECK(np_parse_ethernet_frame(frame, ETH_LEN + IP_LEN + 10, &info) ==
        NP_ERR_TRUNCATED);
  CHECK(np_parse_ethernet_frame(frame, ETH_LEN + 5, &info) == NP_ERR_TRUNCATED);
}

static void test_non_ipv4_is_unsupported(void) {
  uint8_t frame[MAX_TEST_FRAME];
  size_t len = build_tcp_frame(frame);
  put_be16(frame + 12, 0x86DD); /* IPv6 ethertype */

  np_packet_info info;
  CHECK(np_parse_ethernet_frame(frame, len, &info) == NP_ERR_UNSUPPORTED);
}

static void test_malformed_ihl_is_rejected(void) {
  uint8_t frame[MAX_TEST_FRAME];
  size_t len = build_tcp_frame(frame);
  frame[ETH_LEN] = 0x44; /* IHL=4 means a 16-byte header, below the minimum */

  np_packet_info info;
  CHECK(np_parse_ethernet_frame(frame, len, &info) == NP_ERR_MALFORMED);
}

static void test_other_protocol_has_zero_ports(void) {
  uint8_t frame[MAX_TEST_FRAME];
  uint8_t icmp[8] = {8, 0, 0, 0, 0, 1, 0, 1};
  size_t len = build_ipv4_frame(frame, 1, icmp, sizeof(icmp));

  np_packet_info info;
  CHECK(np_parse_ethernet_frame(frame, len, &info) == NP_OK);
  CHECK(info.ip_protocol == 1);
  CHECK(info.src_port == 0);
  CHECK(info.dst_port == 0);
}

static void test_hex_decode(void) {
  uint8_t out[4];
  size_t out_len = 0;

  CHECK(np_hex_decode("0aFf10", out, sizeof(out), &out_len) == NP_OK);
  CHECK(out_len == 3);
  CHECK(out[0] == 0x0A && out[1] == 0xFF && out[2] == 0x10);

  CHECK(np_hex_decode("abc", out, sizeof(out), &out_len) == NP_ERR_MALFORMED);
  CHECK(np_hex_decode("zz", out, sizeof(out), &out_len) == NP_ERR_MALFORMED);
  CHECK(np_hex_decode("0102030405", out, sizeof(out), &out_len) ==
        NP_ERR_TRUNCATED);
}

static void test_null_arguments(void) {
  np_packet_info info;
  uint8_t byte = 0;
  size_t out_len = 0;

  CHECK(np_parse_ethernet_frame(NULL, 0, &info) == NP_ERR_ARG);
  CHECK(np_parse_ethernet_frame(&byte, 1, NULL) == NP_ERR_ARG);
  CHECK(np_hex_decode(NULL, &byte, 1, &out_len) == NP_ERR_ARG);
}

int main(void) {
  test_tcp_frame();
  test_udp_frame();
  test_bad_ip_checksum_is_reported();
  test_truncated_l4_is_rejected();
  test_non_ipv4_is_unsupported();
  test_malformed_ihl_is_rejected();
  test_other_protocol_has_zero_ports();
  test_hex_decode();
  test_null_arguments();

  printf("%d checks, %d failures\n", checks, failures);
  return failures == 0 ? 0 : 1;
}
