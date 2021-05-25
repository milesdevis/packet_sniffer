## A simple packet sniffer made using the pcap library

To compile, simply run the following from the repository folder (requires libpcap to be installed on the system):
```
make
```

To execute the program, use the following command from the build folder:
```
./sniffer [ --output filename ] "expression"
```
Where expression is a pcap filter expression. On unix systems, run `man pcap-filter` for more information. Examples are:
* `tcp host <ip>`
* `host www.google.com`
* `ip`

All output will be written to the terminal and, optionally, to a file in the csv format (in case the flag `--output` is provided). Output is displayed in the following format:
```
Packet Count: <count>
Recieved Packet size : <size>
	ETH:	<source physical address> -> <de3stination physical address>	<network layer protocol>
	<network layer protocol>:	<network layer protocol header data>
	<transport layer protocol>:	<transport layer protocol data>
		<full payload>
```

The csv output contains the following fields:
* ethr proto
* ip proto
* src psysical addr
* src ip addr
* src port
* dst psysical addr
* dst ip addr
* dst port
* checksum
* expected checksum
* sequence
* ack

Protocols currently supported:
* Ethernet
* IP
* TCP
* UDP
