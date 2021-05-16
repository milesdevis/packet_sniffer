#include "ip.h"

#include <netinet/in.h>
#include <arpa/inet.h>

struct ip_header
{
	u_int8_t ip_vhl;
#define IP_V(ip) (((ip)->ip_vhl & 0xf0) >> 4)
#define IP_HL(ip) ((ip)->ip_vhl & 0x0f)
	u_int8_t ip_tos;
	u_int16_t ip_len;
	u_int16_t ip_id;
	u_int16_t ip_off;
#define	IP_DF 0x4000
#define	IP_MF 0x2000
#define	IP_OFFMASK 0x1fff
	u_int8_t ip_ttl;
	u_int8_t ip_p;
	u_int16_t ip_sum;
	struct in_addr ip_src;
	struct in_addr ip_dst;
};

int parse_ip_packet(
	const u_char *packet, size_t packet_length, struct ip_packet *out)
{
	const struct ip_header *hdr;
	// u_int length = pkthdr->len;
	u_int hlen,off,version;
	// int i;
	int len;

	if (packet_length < sizeof(struct ip_header))
	{
		fprintf(stderr, "Packet shorter than ip header\n");
		return 0;
	}

	hdr = (struct ip_header*)(packet);

	len	= ntohs(hdr->ip_len);
	hlen = IP_HL(hdr);
	version = IP_V(hdr);

	if (version != 4)
	{
		fprintf(stdout, "Unknown version %d\n", version);
		return 0;
	}

	if (hlen < 5)
	{
		fprintf(stdout, "bad-hlen %d \n", hlen);
		return 0;
	}

	/* see if we have as much packet as we should */
	if (packet_length < len)
	{
		fprintf(stdout, "Truncated IP - %ld bytes missing\n", len - packet_length);
		return 0;
	}

	off = ntohs(hdr->ip_off);
	if((off & 0x1fff) != 0)
	{
		fprintf(stdout, "IP packet is not the first fragment\n");
		return 0;
	}

	out->src_ip = inet_ntoa(hdr->ip_src);
	out->dst_ip = inet_ntoa(hdr->ip_dst);
	out->version = version;
	out->payload = packet + hlen;
	out->payload_length = packet_length - hlen;

	return 1;
}

void print_ip_packet(struct ip_packet *hdr, FILE *output)
{
	fprintf(output, "\tIP:\t%d\t%s -> %s\n",
		hdr->version, hdr->src_ip, hdr->dst_ip);
}
