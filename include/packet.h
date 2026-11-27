#ifndef NP_PACKET_H
#define NP_PACKET_H

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef enum np_status {
    NP_OK = 0,
    NP_ERR_ARG,
    NP_ERR_TRUNCATED,
    NP_ERR_UNSUPPORTED,
    NP_ERR_MALFORMED
} np_status;

#define NP_IP_PROTO_TCP 6u
#define NP_IP_PROTO_UDP 17u

typedef struct np_packet_info {
    uint8_t  src_mac[6];
    uint8_t  dst_mac[6];
    uint8_t  src_ip[4];
    uint8_t  dst_ip[4];
    uint8_t  ip_protocol;
    uint8_t  ip_checksum_ok;
    uint16_t src_port;
    uint16_t dst_port;
    size_t   payload_length;
} np_packet_info;

/* Parses an Ethernet II frame carrying IPv4. TCP and UDP ports are extracted;
 * other IP protocols are reported as NP_OK with zero ports. Non-IPv4 frames
 * return NP_ERR_UNSUPPORTED. */
np_status np_parse_ethernet_frame(const uint8_t *data, size_t len, np_packet_info *info);

/* Decodes a NUL-terminated string of hex digit pairs into out. */
np_status np_hex_decode(const char *hex, uint8_t *out, size_t out_cap, size_t *out_len);

const char *np_status_str(np_status status);

#ifdef __cplusplus
}
#endif

#endif /* NP_PACKET_H */
