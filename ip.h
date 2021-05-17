#ifndef IP_H
#define IP_H

#include <stdio.h>
#include <stdlib.h>
#include <pcap.h>

#define IP_PROTOCOL_ICMP 1
#define IP_PROTOCOL_TCP 6
#define IP_PROTOCOL_UDP 17

struct ip_packet
{
	char *src_ip;
	char *dst_ip;
	u_int32_t pseudo_hdr;
	u_int version;
	u_int protocol;
	const u_char *payload;
	size_t payload_length;
};

int parse_ip_packet(
	const u_char *packet, size_t packet_length, struct ip_packet *out);

void print_ip_packet(struct ip_packet *hdr, FILE *output);

#endif
