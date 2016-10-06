## A simple packet sniffer using pcap library:

- To install, clone the repo and then cd into the repo
- Then run the following:
```
gcc sniffer.c -o sniffer -lpcap
```
- Then after it compiles:
```
./sniffer ip 
```

You can also replace "ip" in 3 with tcp, arp, etc

The packet sniffer counts the packet number, packet length and displays the payload. 
