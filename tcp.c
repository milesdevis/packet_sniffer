#include "tcp.h"

#include <netinet/in.h>
#include <arpa/inet.h>

struct tcp_header
{
	u_short th_sport;
	u_short th_dport;
	u_int th_seq;
	u_int th_ack;
	u_char th_offx2;
#define TH_OFF(th)	(((th)->th_offx2 & 0xf0) >> 4)
	u_char th_flags;
#define TH_FIN 0x01
#define TH_SYN 0x02
#define TH_RST 0x04
#define TH_PUSH 0x08
#define TH_ACK 0x10
#define TH_URG 0x20
#define TH_ECE 0x40
#define TH_CWR 0x80
#define TH_FLAGS (TH_FIN|TH_SYN|TH_RST|TH_ACK|TH_URG|TH_ECE|TH_CWR)
	u_short th_win;
	u_short th_sum;
	u_short th_urp;
};

u_int16_t calculate_tcp_checksum(
	u_int32_t ip_pseudo_hdr, const u_char *packet, size_t packet_length)
{
	int i;
	u_int16_t d;
	u_int32_t c = ip_pseudo_hdr;

	for (i = 0; i < packet_length; i++)
	{
		d = packet[i];

		// skip the checksum on the header
		if (i == 16 || i == 17)
			continue;

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

int parse_tcp_packet(
	const u_char *packet, size_t packet_length, struct tcp_packet *out,
	u_int32_t ip_pseudo_hdr)
{
	struct tcp_header *hdr;

	if (packet_length < sizeof(struct tcp_header))
	{
		fprintf(stderr, "Packet shorter than TCP header\n");
		return 0;
	}

	hdr = (struct tcp_header*) packet;

    out->src_port = ntohs(hdr->th_sport);
    out->dst_port = ntohs(hdr->th_dport);
	out->sequence = ntohl(hdr->th_seq);
	out->ack = ntohl(hdr->th_ack);
	out->payload = packet + sizeof(struct tcp_header);
	out->payload_length = packet_length - sizeof(struct tcp_header);

    out->recv_checksum = ntohs(hdr->th_sum);
    out->calc_checksum = calculate_tcp_checksum(ip_pseudo_hdr, packet, packet_length);

	return 1;
}

void print_tcp_packet(struct tcp_packet *pkt, FILE *output)
{
	fprintf(output, "\tTCP:\t%d -> %d", pkt->src_port, pkt->dst_port);

	if (pkt->recv_checksum == pkt->calc_checksum)
	{
		fprintf(output, "\tchecksum: OK (0x%02x)", pkt->calc_checksum);
	}
	else
	{
		fprintf(output, "\tchecksum: ERR (0x%04x != 0x%04x)",
			pkt->recv_checksum, pkt->calc_checksum);
	}

	fprintf(output, "\tseq: %u\tack: %u\n", pkt->sequence, pkt->ack);
}
