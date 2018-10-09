#include "defines.h"
#include "misc.h"

void extended_verbose_mode(struct ether_hdr* eth, unsigned char* packet, struct options* opt){
	static int packet_counter = 0;

	if(packet_counter == opt->show_n_first_packets)
		exit(0);

	packet_counter++;
	// printf("Total: %d Current: %d\n", opt->show_n_first_packets, packet_counter); //DEBUG

	if(eth->ether_type == htons(0x0800)) { //IP
		struct ip_hdr* ip_header;
		ip_header = build_ip_header(packet);
		if(ip_header->ip_proto == ICMP){ // IP-ICMP
			printf("This is an ICMP Packet.\n");// DEBUG
		}
		else if(ip_header->ip_proto == UDP){ // IP-UDP
			printf("This is an UDP Packet.\n");// DEBUG
		}
		else if(ip_header->ip_proto == TCP){ // IP-TCP
			printf("This is a TCP Packet.\n");// DEBUG
		}
		else {
			printf("This analyzer doesn't know this packet's protocol.\n");
		}
	} else if(eth->ether_type == htons(0x0806)) { // ARP
		printf("This is an ARP Packet.\n");// DEBUG
	} else {
		printf("This analyzer doesn't know this packet's protocol.\n");
	}
}
