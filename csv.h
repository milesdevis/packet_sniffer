#ifndef CSV_H
#define CSV_H

#include "ethernet.h"
#include "ip.h"
#include "tcp.h"
#include "udp.h"
#include "util.h"

void csv_write_header(FILE *output);

void csv_write_record(FILE *output,
    struct ethernet_packet *ethr,
    struct ip_packet *ip,
    struct udp_packet *udp,
    struct tcp_packet *tcp);

#endif
