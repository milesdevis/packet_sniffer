#include "udp.h"

#include <netinet/in.h>
#include <arpa/inet.h>

#include "util.h"

struct udp_header
{
	u_int16_t src_port;
	u_int16_t dst_port;
	u_int16_t length;
	u_int16_t checksum;
} __attribute__((packed));

u_int16_t calculate_checksum(
	struct udp_header *hdr, u_int32_t ip_pseudo_hdr,
	const u_char *payload, size_t payload_length)
{
	int i;
	u_int16_t d;
	u_int32_t c = ip_pseudo_hdr;

	c += ntohs(hdr->src_port);
	c += ntohs(hdr->dst_port);
	c += ntohs(hdr->length);

	for (i = 0; i < payload_length; i++)
	{
		d = payload[i];

		if (i % 2 == 0)
		{
			c += d << 8;
		}
		else
		{
			c += d;
		}
	}

	while ((c & 0xffff0000) > 0)
		c = ((c & 0xffff0000) >> 16) + (c & 0x0000ffff);

	c = ~c;

	return (u_int16_t) c;
}

int parse_udp_packet(
	const u_char *packet, size_t packet_length, struct udp_packet *out,
	u_int32_t ip_pseudo_hdr)
{
	struct udp_header *hdr;

	if (packet_length < sizeof(struct udp_header))
	{
		fprintf(stderr, "Packet shorter than udp header\n");
		return 0;
	}

	hdr = (struct udp_header*) packet;

	out->src_port = ntohs(hdr->src_port);
	out->dst_port = ntohs(hdr->dst_port);
	out->recv_checksum = ntohs(hdr->checksum);
	out->payload = packet + sizeof(struct udp_header);
	out->payload_length = packet_length - sizeof(struct udp_header);

	out->calc_checksum = calculate_checksum(hdr, ip_pseudo_hdr, out->payload, out->payload_length);

	return 1;
}

void print_udp_packet(struct udp_packet *pkt, FILE *output)
{
	fprintf(output, "\tUDP:\t%d -> %d", pkt->src_port, pkt->dst_port);

	if (pkt->recv_checksum == pkt->calc_checksum)
	{
		fprintf(output, "\tchecksum: OK (0x%02x)\n", pkt->calc_checksum);
	}
	else
	{
		fprintf(output, "\tchecksum: ERR (0x%04x != 0x%04x)\n",
			pkt->recv_checksum, pkt->calc_checksum);
	}
}
