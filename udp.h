#ifndef UDP_H
#define UDP_H

#include <stdio.h>
#include <stdlib.h>
#include <pcap.h>

struct udp_packet
{
    int src_port;
    int dst_port;
    u_int16_t recv_checksum;
    u_int16_t calc_checksum;
    const u_char *payload;
    size_t payload_length;
};

int parse_udp_packet(
    const u_char *packet, size_t packet_length, struct udp_packet *out,
    u_int32_t ip_pseudo_hdr);

void print_udp_packet(struct udp_packet *pkt, FILE *output);

#endif
