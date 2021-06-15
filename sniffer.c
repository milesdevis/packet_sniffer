#include <ctype.h>
#include <pcap.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>

#include "ethernet.h"
#include "ip.h"
#include "tcp.h"
#include "udp.h"
#include "util.h"

#include "csv.h"

struct callback_args
{
	FILE *csv_output;
};

void callback(u_char *args, const struct pcap_pkthdr* pkthdr, const u_char* packet)
{
	int i = 0;
	static int count = 0;
	struct callback_args *cargs = (struct callback_args*) args;
	struct ethernet_packet ethr;
	struct ip_packet ip;
	struct tcp_packet tcp;
	struct udp_packet udp;

	printf("Packet Count: %d\n", ++count);
	printf("Recieved Packet size : %d\n", pkthdr->len);

	if (!parse_ethernet_packet(args, pkthdr, packet, &ethr))
	{
		printf("Failed to parse ethernet header\n\n");
		return;
	}

	print_ethernet_packet(&ethr, stdout);

	if (ethr.type != ETHERTYPE_IP)
	{
		printf("\tUnknown protocol\n\n");
		return;
	}

	if (!parse_ip_packet(ethr.payload, ethr.payload_length, &ip))
	{
		printf("Failed to parse ip header\n\n");
		return;
	}

	print_ip_packet(&ip, stdout);

	if (ip.protocol == IP_PROTOCOL_ICMP)
	{
		printf("\t(ICMP)\n");
	}
	else if (ip.protocol == IP_PROTOCOL_TCP)
	{
		if (!parse_tcp_packet(ip.payload, ip.payload_length, &tcp, ip.pseudo_hdr))
		{
			printf("Failed to parse TCP header\n\n");
			return;
		}

		print_tcp_packet(&tcp, stdout);
	}
	else if (ip.protocol == IP_PROTOCOL_UDP)
	{
		if (!parse_udp_packet(ip.payload, ip.payload_length, &udp, ip.pseudo_hdr))
		{
			printf("Failed to parse UDP header\n\n");
			return;
		}

		print_udp_packet(&udp, stdout);
	}

	print_packet(packet, pkthdr->caplen, stdout);
	printf("\n");

	if (cargs->csv_output)
	{
		csv_write_record(cargs->csv_output, &ethr, &ip, &udp, &tcp);
		fflush(cargs->csv_output);
	}
}

int parse_args(int argc, char **argv, char **expr, char **filename)
{
	*expr = NULL;
	*filename = NULL;

	if (argc < 2)
		return 0;

	if (strcmp(argv[1], "--output") == 0)
	{
		if (argc != 4)
			return 0;

		*filename = argv[2];
		*expr = argv[3];
	}
	else
	{
		if (argc != 2)
			return 0;

		*expr = argv[1];
	}
}

int main(int argc, char **argv)
{
	int i;
	char *dev, *expr = NULL, *filename = NULL;
	char errbuf[PCAP_ERRBUF_SIZE];
	pcap_t* descr;
	const u_char *packet;
	struct pcap_pkthdr hdr;
	struct ether_header *eptr;
	struct bpf_program fp;
	bpf_u_int32 maskp;
	bpf_u_int32 netp;
	struct callback_args cargs;

	if (!parse_args(argc, argv, &expr, &filename))
	{
		fprintf(stdout, "Usage: %s [ --output filename ] \"expression\"\n", argv[0]);
		return 0;
	}

	if (filename)
	{
		cargs.csv_output = fopen(filename, "w");

		csv_write_header(cargs.csv_output);
	}
	else
	{
		cargs.csv_output = NULL;
	}

	// pcap_if_t *alldevsp;       /* list of interfaces */

	// if (pcap_findalldevs (&alldevsp, errbuf) < 0)   
	// {
	// 	fprintf (stderr, "%s", errbuf);
	// 	exit (1);
	// }
	// while (alldevsp != NULL)
	// {
	// 	printf ("%s\n", alldevsp->name);
	// 	alldevsp = alldevsp->next;
	// }

	/*Get a device*/

	dev = pcap_lookupdev(errbuf);
	if (dev == NULL)
	{
		fprintf(stderr, "%s\n",errbuf);
		exit(1);
	}

	fprintf(stdout, "listening on device \"%s\"\n", dev);

	/*Get network addr and mask*/
	pcap_lookupnet(dev, &netp, &maskp, errbuf);

	descr = pcap_open_live(dev, BUFSIZ, 1, -1, errbuf);

	if(descr == NULL)
	{
		printf("pcap_open_live():%s\n", errbuf);
		exit(1);
	}

	if(pcap_compile(descr,&fp, expr, 0, netp) == -1)
	{
		fprintf(stderr, "Error calling pcap_compile\n");
		exit(1);
	}

	if(pcap_setfilter(descr,&fp) == -1)
	{
		fprintf(stderr, "Error setting filter!\n");
		exit(1);
	}

	pcap_loop(descr, -1, callback, (u_char*) &cargs);
	return 0;
}
