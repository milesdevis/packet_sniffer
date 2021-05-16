#ifndef ETHERNET_H
#define ETHERNET_H

#include <stdio.h>
#include <stdlib.h>
#include <pcap.h>

#define ETHERTYPE_IP 0x0800
#define ETHERTYPE_ARP 0x0806

struct ethernet_header
{
	char *dst_addr;
	char *src_addr;
	u_int16_t type;
};

int parse_ethernet_header(
	u_char *args, const struct pcap_pkthdr* pkthdr,
    const u_char* packet, struct ethernet_header *out);

void print_ethernet_header(struct ethernet_header *hdr, FILE *output);

#endif
