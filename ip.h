#ifndef IP_H
#define IP_H

#include <stdio.h>
#include <stdlib.h>
#include <pcap.h>

struct ip_packet
{
	char *src_ip;
	char *dst_ip;
	u_int version;
	const u_char *payload;
	size_t payload_length;
};

int parse_ip_packet(
	const u_char *packet, size_t packet_length, struct ip_packet *out);

void print_ip_packet(struct ip_packet *hdr, FILE *output);

#endif
