#ifndef UTIL_H
#define UTIL_H

#include <stdio.h>
#include <stdlib.h>
#include <pcap.h>

void print_packet(const u_char *packet, size_t packet_length, FILE *output);

#endif