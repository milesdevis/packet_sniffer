#include <ctype.h>
#include <pcap.h>
#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
// #include <sys/socket.h>
// #include <netinet/in.h>
// #include <arpa/inet.h>
// #include <netinet/if_ether.h>

#include "ethernet.h"
#include "ip.h"
#include "udp.h"
#include "util.h"

void callback(u_char *args, const struct pcap_pkthdr* pkthdr, const u_char* packet)
{
	int i = 0;
	static int count = 0;
	struct ethernet_packet ethr;
	struct ip_packet ip;
	struct udp_packet udp;

	printf("Packet Count: %d\n", ++count);
	printf("Recieved Packet size : %d\n", pkthdr->len);
	// printf("Payload:\n");

	if (!parse_ethernet_packet(args, pkthdr, packet, &ethr))
	{
		printf("Failed to parse ethernet header\n\n");
		return;
	}

	print_ethernet_packet(&ethr, stdout);
	free(ethr.dst_addr);
	free(ethr.src_addr);

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
		printf("\t(TCP)\n");
	}
	else if (ip.protocol == IP_PROTOCOL_UDP)
	{
		if (!parse_udp_packet(ip.payload, ip.payload_length, &udp, ip.pseudo_hdr))
		{
			printf("Failed to parse udp header\n\n");
			return;
		}

		print_udp_packet(&udp, stdout);
	}

	print_packet(ethr.payload, ethr.payload_length, stdout);
	printf("\n");
}

int main(int argc, char **argv)
{
	int i;
	char *dev;
	char errbuf[PCAP_ERRBUF_SIZE];
	pcap_t* descr;
	const u_char *packet;
	struct pcap_pkthdr hdr;
	struct ether_header *eptr;
	struct bpf_program fp;
	bpf_u_int32 maskp;
	bpf_u_int32 netp;

	if(argc != 2)
	{
		fprintf(stdout, "Usage: %s \"expression\"\n", argv[0]);
		return 0;
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

	// dev = pcap_lookupdev(errbuf);
	dev = "lo";
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

	if(pcap_compile(descr,&fp, argv[1], 0, netp) == -1)
	{
		fprintf(stderr, "Error calling pcap_compile\n");
		exit(1);
	}

	if(pcap_setfilter(descr,&fp) == -1)
	{
		fprintf(stderr, "Error setting filter!\n");
		exit(1);
	}

	pcap_loop(descr,-1, callback, NULL);
	return 0;
}
