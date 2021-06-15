#include "ip.h"

#include <string.h>

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
} __attribute__((__packed__));

u_int32_t calculate_pseudo_hdr(
	const struct ip_header *hdr, size_t payload_length)
{
	u_int32_t res = 0;

	res += ntohs(hdr->ip_src.s_addr & 0xffff);
	res += ntohs((hdr->ip_src.s_addr >> 16) & 0xffff);

	res += ntohs(hdr->ip_dst.s_addr & 0xffff);
	res += ntohs((hdr->ip_dst.s_addr >> 16) & 0xffff);

	res += hdr->ip_p;
	res += (u_int32_t) payload_length;

	return res;
}

int parse_ip_packet(
	const u_char *packet, size_t packet_length, struct ip_packet *out)
{
	const struct ip_header *hdr;
	u_int hlen,off,version;
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

	strcpy(out->src_ip, inet_ntoa(hdr->ip_src));
	strcpy(out->dst_ip, inet_ntoa(hdr->ip_dst));
	out->version = version;
	out->protocol = hdr->ip_p;
	out->payload = packet + hlen * 4;
	out->payload_length = packet_length - hlen * 4;

	out->pseudo_hdr = calculate_pseudo_hdr(hdr, out->payload_length);

	return 1;
}

void print_ip_packet(struct ip_packet *hdr, FILE *output)
{
	int i;

	fprintf(output, "\tIP:\t%s -> %s\t%d\n",
		hdr->src_ip, hdr->dst_ip, hdr->version);
}
