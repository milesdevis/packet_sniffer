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

void callback(u_char *args, const struct pcap_pkthdr* pkthdr, const u_char* packet)
{
	int i = 0;
	static int count = 0;
	struct ethernet_packet ethr;
	struct ip_packet ip;

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

	if (!parse_ip_packet(ethr.payload, ethr.payload_length, &ip))
	{
		printf("Failed to parse ip header\n\n");
		return;
	}

	print_ip_packet(&ip, stdout);

	printf("\n");

	// for (i = 0; i < pkthdr->len; i++)
	// {
	// 	if (isprint(packet[i]))
	// 		printf("%c ", packet[i]);
	// 	else
	// 		printf(" . ");
	// 	if((i%16==0 && i!=0)|| i == pkthdr->len-1)
	// 		printf("\n");
	// }

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

	/*Get a device*/

	dev = pcap_lookupdev(errbuf);
	if (dev == NULL)
	{
		fprintf(stderr, "%s\n",errbuf);
		exit(1);
	}

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

















