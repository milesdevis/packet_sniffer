#ifndef ETHERNET_H
#define ETHERNET_H

#include <stdio.h>
#include <stdlib.h>
#include <pcap.h>

#define ETHERTYPE_IP 0x0800
#define ETHERTYPE_ARP 0x0806

struct ethernet_packet
{
	char dst_addr[20];
	char src_addr[20];
	u_int16_t type;
	const u_char *payload;
	size_t payload_length;
};

int parse_ethernet_packet(
	u_char *args, const struct pcap_pkthdr* pkthdr,
    const u_char* packet, struct ethernet_packet *out);

void print_ethernet_packet(struct ethernet_packet *hdr, FILE *output);

#endif
