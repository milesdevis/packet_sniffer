#include "ethernet.h"

#define ETHERNET_ADDR_LENGTH 6

struct ethernet_addr
{
	u_int8_t addr[ETHERNET_ADDR_LENGTH];
};

struct ethernet_header
{
	struct ethernet_addr dst_addr;
	struct ethernet_addr src_addr;
	u_int16_t type;
} __attribute__((__packed__));

char* ether_addr_to_str(struct ethernet_addr *addr)
{
	char *res;

	res = (char*) malloc(sizeof(char) * (ETHERNET_ADDR_LENGTH * 2));
	sprintf(res, "%02x:%02x:%02x:%02x:%02x:%02x",
		addr->addr[0], addr->addr[1], addr->addr[2],
		addr->addr[3], addr->addr[4], addr->addr[5]);

	return res;
}

int parse_ethernet_packet(
	u_char *args, const struct pcap_pkthdr* pkthdr,
	const u_char* packet, struct ethernet_packet *out)
{
	struct ethernet_header *hdr;

	if (pkthdr->caplen < sizeof(struct ethernet_header))
	{
		fprintf(stderr, "Packet shorter than ethernet header\n");
		return 0;
	}

	hdr = (struct ethernet_header*) packet;
	// ether_type = ntohs(eptr->ether_type);
	out->type = (hdr->type << 8) | (hdr->type >> 8);
	out->dst_addr = ether_addr_to_str(&hdr->dst_addr);
	out->src_addr = ether_addr_to_str(&hdr->src_addr);
	out->payload = packet + sizeof(struct ethernet_header);
	out->payload_length = pkthdr->caplen - sizeof(struct ethernet_header);

	return 1;
}

void print_ethernet_packet(struct ethernet_packet *packet, FILE *output)
{
	fprintf(output, "\tETH:\t%s -> %s", packet->src_addr, packet->dst_addr);

    if (packet->type == ETHERTYPE_IP)
    {
        fprintf(output,"\t(IP)\n");
    }
	else if (packet->type == ETHERTYPE_ARP)
    {
        fprintf(output,"\t(ARP)\n");
	}
	else
	{
        fprintf(output,"\t(?)\n");
    }
}
