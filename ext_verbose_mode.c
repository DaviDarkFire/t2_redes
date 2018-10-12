#include "defines.h"
#include "misc.h"
#include "ext_verbose_mode.h"

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
			print_ether_protocol(eth, packet_counter, get_packet_size(packet));
		}
		else if(ip_header->ip_proto == UDP){ // IP-UDP
			printf("This is an UDP Packet.\n");// DEBUG
			print_ether_protocol(eth, packet_counter, get_packet_size(packet));
		}
		else if(ip_header->ip_proto == TCP){ // IP-TCP
			printf("This is a TCP Packet.\n");// DEBUG
			struct tcp_hdr* tcp_header =  build_tcp_header(packet);

			print_ether_protocol(eth, packet_counter, get_packet_size(packet));
			print_tcp_protocol(tcp_header);
		}
		else {
			printf("This analyzer doesn't know this packet's protocol.\n");
		}
	} else if(eth->ether_type == htons(0x0806)) { // ARP
		printf("This is an ARP Packet.\n");// DEBUG
		print_ether_protocol(eth, packet_counter, get_packet_size(packet));
	} else {
		printf("This analyzer doesn't know this packet's protocol.\n");
	}
}


void print_ether_protocol(struct ether_hdr* eth, int packet_counter, int packet_size){
	char protocol[3];

	if(eth->ether_type == htons(0x0800))

		strcpy(protocol, "IP");

	else
		strcpy(protocol, "ARP");

	
	printf("ETHER: ----- Ether Header -----\n");
	printf("ETHER:\n");
	printf("ETHER: Packet %d\n", packet_counter);
	printf("ETHER: Packet size = %d bytes\n", packet_size);
	printf("ETHER: Destination = %02X:%02X:%02X:%02X:%02X:%02X,\n", eth->ether_dhost[0], eth->ether_dhost[1], eth->ether_dhost[2],eth->ether_dhost[3], eth->ether_dhost[4], eth->ether_dhost[5]);
	printf("ETHER: Source      = %02X:%02X:%02X:%02X:%02X:%02X,\n", eth->ether_shost[0], eth->ether_shost[1], eth->ether_shost[2],eth->ether_shost[3], eth->ether_shost[4], eth->ether_shost[5]);
	printf("ETHER: Ethertype   = %d (%s)\n",  eth->ether_type, protocol);
}

void print_ip_protocol(struct ip_hdr* ip){
	printf("IP: ----- IP Header -----\n");


}

void print_tcp_protocol(struct tcp_hdr* tcp_header){
	printf("TCP: ----- TCP Header -----\n");
	printf("TCP: Source port = %d\n", tcp_header->src_port);
	printf("TCP: Destination port = %d\n", tcp_header->dst_port);
	printf("TCP: Sequence Number = %d\n", tcp_header->seq_num);
	printf("TCP: Acknowledgement number = %d\n", tcp_header->ack_num);
	printf("TCP: Data offset = %d bytes\n", tcp_header->data_offset);


}