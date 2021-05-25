#include "csv.h"

void csv_write_header(FILE *output)
{
    fprintf(output, "ethr proto;ip proto;src psysical addr;src ip addr;src port;dst psysical addr;dst ip addr;dst port;checksum;expected checksum;sequence;ack;\n");
}

void csv_write_record(FILE *output,
    struct ethernet_packet *ethr,
    struct ip_packet *ip,
    struct udp_packet *udp,
    struct tcp_packet *tcp)
{
    switch (ethr->type)
    {
    case ETHERTYPE_IP:
        fprintf(output, "IP;");
        break;

    case ETHERTYPE_ARP:
        fprintf(output, "ARP;;;;;;;;;;;;\n");
        return;

    default:
        fprintf(output, "?;;;;;;;;;;;;\n");
        return;
    }

    switch (ip->protocol)
    {
    case IP_PROTOCOL_ICMP:
        fprintf(output, "ICMP;;;;;;;;;;;\n");
        break;

    case IP_PROTOCOL_TCP:
        fprintf(output, "TCP;");
        fprintf(output, "%s;%s;%d;", ethr->src_addr, ip->src_ip, tcp->src_port);
        fprintf(output, "%s;%s;%d;", ethr->dst_addr, ip->dst_ip, tcp->dst_port);
        fprintf(output, "0x%04x;0x%04x;%u;%u;\n",
            tcp->recv_checksum, tcp->calc_checksum, tcp->sequence, tcp->ack);
        break;

    case IP_PROTOCOL_UDP:
        fprintf(output, "UDP;");
        fprintf(output, "%s;%s;%d;", ethr->src_addr, ip->src_ip, udp->src_port);
        fprintf(output, "%s;%s;%d;", ethr->dst_addr, ip->dst_ip, udp->dst_port);
        fprintf(output, "0x%04x;0x%04x;;;\n",
            udp->recv_checksum, udp->calc_checksum);
        break;

    default:
        fprintf(output, "?;;;;;;;;;;;\n");
        break;
    }
}
