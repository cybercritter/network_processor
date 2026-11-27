#include "packet.h"

#include <stdio.h>
#include <string.h>

#define MAX_FRAME_BYTES 32768u
#define MAX_LINE_CHARS (MAX_FRAME_BYTES * 2u + 2u)

static void print_frame_summary(size_t index, const uint8_t *frame,
                                size_t len) {
  np_packet_info info;
  np_status status = np_parse_ethernet_frame(frame, len, &info);

  if (status != NP_OK) {
    printf("frame %zu: %s\n", index, np_status_str(status));
    return;
  }

  printf("frame %zu: %u.%u.%u.%u:%u -> %u.%u.%u.%u:%u proto=%s payload=%zu "
         "checksum=%s\n",
         index, info.src_ip[0], info.src_ip[1], info.src_ip[2], info.src_ip[3],
         info.src_port, info.dst_ip[0], info.dst_ip[1], info.dst_ip[2],
         info.dst_ip[3], info.dst_port,
         info.ip_protocol == NP_IP_PROTO_TCP   ? "tcp"
         : info.ip_protocol == NP_IP_PROTO_UDP ? "udp"
                                               : "other",
         info.payload_length, info.ip_checksum_ok ? "ok" : "bad");
}

static int process_stream(FILE *in) {
  static char line[MAX_LINE_CHARS + 1];
  static uint8_t frame[MAX_FRAME_BYTES];
  size_t index = 0;
  int failures = 0;

  while (fgets(line, sizeof(line), in) != NULL) {
    size_t n = strlen(line);
    if (n == sizeof(line) - 1 && line[n - 1] != '\n') {
      fprintf(stderr, "error: line %zu exceeds %u hex characters\n", index + 1,
              MAX_LINE_CHARS);
      return 1;
    }
    while (n > 0 &&
           (line[n - 1] == '\n' || line[n - 1] == '\r' || line[n - 1] == ' ')) {
      line[--n] = '\0';
    }
    if (n == 0) {
      continue;
    }

    index++;
    size_t frame_len = 0;
    np_status status = np_hex_decode(line, frame, sizeof(frame), &frame_len);
    if (status != NP_OK) {
      printf("frame %zu: invalid hex (%s)\n", index, np_status_str(status));
      failures++;
      continue;
    }
    print_frame_summary(index, frame, frame_len);
  }
  return failures;
}

int main(int argc, char **argv) {
  if (argc > 2) {
    fprintf(stderr, "usage: %s [hex_frames_file]\n", argv[0]);
    return 2;
  }

  FILE *in = stdin;
  if (argc == 2) {
    in = fopen(argv[1], "r");
    if (in == NULL) {
      fprintf(stderr, "error: cannot open '%s'\n", argv[1]);
      return 1;
    }
  }

  int failures = process_stream(in);

  if (in != stdin) {
    fclose(in);
  }
  return failures == 0 ? 0 : 1;
}
