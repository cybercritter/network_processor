#include "packet.h"

#include <string.h>

#define ETH_HEADER_LEN   14u
#define ETH_TYPE_IPV4    0x0800u
#define IPV4_MIN_HEADER  20u
#define TCP_MIN_HEADER   20u
#define UDP_HEADER_LEN   8u

static uint16_t read_be16(const uint8_t *p)
{
    return (uint16_t)((p[0] << 8) | p[1]);
}

static int ipv4_checksum_ok(const uint8_t *header, size_t header_len)
{
    uint32_t sum = 0;

    for (size_t i = 0; i + 1 < header_len; i += 2) {
        sum += read_be16(header + i);
    }
    while (sum >> 16) {
        sum = (sum & 0xFFFFu) + (sum >> 16);
    }
    return sum == 0xFFFFu;
}

np_status np_parse_ethernet_frame(const uint8_t *data, size_t len, np_packet_info *info)
{
    if (data == NULL || info == NULL) {
        return NP_ERR_ARG;
    }
    memset(info, 0, sizeof(*info));

    if (len < ETH_HEADER_LEN) {
        return NP_ERR_TRUNCATED;
    }
    memcpy(info->dst_mac, data, 6);
    memcpy(info->src_mac, data + 6, 6);
    if (read_be16(data + 12) != ETH_TYPE_IPV4) {
        return NP_ERR_UNSUPPORTED;
    }

    const uint8_t *ip = data + ETH_HEADER_LEN;
    size_t ip_avail = len - ETH_HEADER_LEN;
    if (ip_avail < IPV4_MIN_HEADER) {
        return NP_ERR_TRUNCATED;
    }
    if ((ip[0] >> 4) != 4) {
        return NP_ERR_MALFORMED;
    }

    size_t ip_header_len = (size_t)(ip[0] & 0x0Fu) * 4u;
    if (ip_header_len < IPV4_MIN_HEADER) {
        return NP_ERR_MALFORMED;
    }
    if (ip_avail < ip_header_len) {
        return NP_ERR_TRUNCATED;
    }

    size_t ip_total_len = read_be16(ip + 2);
    if (ip_total_len < ip_header_len) {
        return NP_ERR_MALFORMED;
    }
    /* Clamp to the captured bytes; the frame may carry Ethernet padding. */
    if (ip_total_len > ip_avail) {
        ip_total_len = ip_avail;
    }

    info->ip_protocol = ip[9];
    info->ip_checksum_ok = (uint8_t)ipv4_checksum_ok(ip, ip_header_len);
    memcpy(info->src_ip, ip + 12, 4);
    memcpy(info->dst_ip, ip + 16, 4);

    const uint8_t *l4 = ip + ip_header_len;
    size_t l4_avail = ip_total_len - ip_header_len;
    size_t l4_header_len = 0;

    if (info->ip_protocol == NP_IP_PROTO_TCP) {
        if (l4_avail < TCP_MIN_HEADER) {
            return NP_ERR_TRUNCATED;
        }
        l4_header_len = (size_t)(l4[12] >> 4) * 4u;
        if (l4_header_len < TCP_MIN_HEADER) {
            return NP_ERR_MALFORMED;
        }
    } else if (info->ip_protocol == NP_IP_PROTO_UDP) {
        if (l4_avail < UDP_HEADER_LEN) {
            return NP_ERR_TRUNCATED;
        }
        l4_header_len = UDP_HEADER_LEN;
    }

    if (l4_header_len == 0) {
        return NP_OK;
    }
    if (l4_avail < l4_header_len) {
        return NP_ERR_TRUNCATED;
    }

    info->src_port = read_be16(l4);
    info->dst_port = read_be16(l4 + 2);
    info->payload_length = l4_avail - l4_header_len;
    return NP_OK;
}

static int hex_nibble(char c)
{
    if (c >= '0' && c <= '9') {
        return c - '0';
    }
    if (c >= 'a' && c <= 'f') {
        return c - 'a' + 10;
    }
    if (c >= 'A' && c <= 'F') {
        return c - 'A' + 10;
    }
    return -1;
}

np_status np_hex_decode(const char *hex, uint8_t *out, size_t out_cap, size_t *out_len)
{
    if (hex == NULL || out == NULL || out_len == NULL) {
        return NP_ERR_ARG;
    }

    size_t hex_len = strlen(hex);
    if (hex_len % 2 != 0) {
        return NP_ERR_MALFORMED;
    }
    if (hex_len / 2 > out_cap) {
        return NP_ERR_TRUNCATED;
    }

    for (size_t i = 0; i < hex_len; i += 2) {
        int hi = hex_nibble(hex[i]);
        int lo = hex_nibble(hex[i + 1]);
        if (hi < 0 || lo < 0) {
            return NP_ERR_MALFORMED;
        }
        out[i / 2] = (uint8_t)((hi << 4) | lo);
    }
    *out_len = hex_len / 2;
    return NP_OK;
}

const char *np_status_str(np_status status)
{
    switch (status) {
    case NP_OK:              return "ok";
    case NP_ERR_ARG:         return "invalid argument";
    case NP_ERR_TRUNCATED:   return "truncated";
    case NP_ERR_UNSUPPORTED: return "unsupported";
    case NP_ERR_MALFORMED:   return "malformed";
    }
    return "unknown";
}
