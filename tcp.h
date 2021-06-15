#ifndef TCP_H
#define TCP_H

#include <stdio.h>
#include <stdlib.h>
#include <pcap.h>

struct tcp_packet
{
    int src_port;
    int dst_port;
	u_int32_t sequence;
	u_int32_t ack;
    u_int16_t recv_checksum;
    u_int16_t calc_checksum;
    u_int8_t flags;
    u_int16_t window;
	const u_char *payload;
    size_t payload_length;
};

int parse_tcp_packet(
	const u_char *packet, size_t packet_length, struct tcp_packet *out, u_int32_t ip_pseudo_hdr);

void print_tcp_packet(struct tcp_packet *hdr, FILE *output);
void print_tcp_flags(u_int8_t flags, FILE *output);

#endif
