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
			print_ip_protocol(ip_header);
		}
		else if(ip_header->ip_proto == UDP){ // IP-UDP
			printf("This is an UDP Packet.\n");// DEBUG
			print_ether_protocol(eth, packet_counter, get_packet_size(packet));
			print_ip_protocol(ip_header);
			struct udp_hdr* udp_header;
			udp_header = build_udp_header(packet);
			print_udp_protocol(udp_header, packet);
		}
		else if(ip_header->ip_proto == TCP){ // IP-TCP
			printf("This is a TCP Packet.\n");// DEBUG
			struct tcp_hdr* tcp_header =  build_tcp_header(packet);

			print_ether_protocol(eth, packet_counter, get_packet_size(packet));
			print_ip_protocol(ip_header);
			print_tcp_protocol(tcp_header, packet);
		}
		else { // IP-UNKNOWN protocol
			printf("This analyzer doesn't know this packet's protocol.\n");
			print_ether_protocol(eth, packet_counter, get_packet_size(packet));
			print_ip_protocol(ip_header);
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

	else if(eth->ether_type == htons(0x0806))
		strcpy(protocol, "ARP");

		else
			strcpy(protocol, "UNKNOWN");


	printf("ETHER: ----- Ether Header -----\n");
	printf("ETHER:\n");
	printf("ETHER: Packet %d\n", packet_counter);
	printf("ETHER: Packet size = %d bytes\n", packet_size);
	printf("ETHER: Destination = %02X:%02X:%02X:%02X:%02X:%02X,\n", eth->ether_dhost[0], eth->ether_dhost[1], eth->ether_dhost[2],eth->ether_dhost[3], eth->ether_dhost[4], eth->ether_dhost[5]);
	printf("ETHER: Source      = %02X:%02X:%02X:%02X:%02X:%02X,\n", eth->ether_shost[0], eth->ether_shost[1], eth->ether_shost[2],eth->ether_shost[3], eth->ether_shost[4], eth->ether_shost[5]);
	printf("ETHER: Ethertype   = %d (%s)\n",  eth->ether_type, protocol);
	printf("ETHER: \n");
}

void print_ip_protocol(struct ip_hdr* ip){
	char protocol[4];

	if(ip->ip_proto == TCP)
		strcpy(protocol,"TCP");
	else if(ip->ip_proto == UDP)
		strcpy(protocol, "UDP");
		else if(ip->ip_proto == ICMP)
			strcpy(protocol, "ICMP");
			else
				strcpy(protocol, "UNKNOWN");

	printf("IP: ----- IP Header -----\n");
	printf("IP: \n");
	printf("IP: Version = %d, header length = %d bytes\n", ip->ip_v, ip->ip_hl);
	printf("IP: Type of service = %2d\n", ip->ip_tos);
	print_ip_tos(ip->ip_tos);
	printf("IP: Total length = %d bytes\n", ip->ip_len);
	printf("IP: Identification = %d\n", ip->ip_id);
	printf("IP: Flags = 0x%x\n", ip->ip_flags);
	print_ip_flags(ip->ip_flags);
	printf("IP: Fragment offset = %d bytes\n", ip->ip_offset);
	printf("IP: Time to live = %d seconds/hops\n", ip->ip_ttl);
	printf("IP: Protocol = %d (%s)\n", ip->ip_proto, protocol);
	printf("IP: Header checksum = %4x\n", ip->ip_csum);
	printf("IP: Source address = %s, %s\n", get_address_as_string_from_uint(ip->ip_src), " "); // TODO: o segundo %s vai o endereço traduzido
	printf("IP: Destination address = %s, %s\n", get_address_as_string_from_uint(ip->ip_dst), " "); // TODO: o segundo %s vai o endereço traduzido
	printf("IP: \n");

}

void print_ip_tos(unsigned char tos){
	unsigned int xor_result;

	xor_result = (tos&11100000) ^ 0b11100000;
	if(xor_result == 0){
		printf("IP       111. .... = network control\n");
	} else {
		xor_result = (tos&11100000) ^ 0b11000000;
		if(xor_result == 0){
			printf("IP       110. .... = internetwork control\n");
		} else {
			xor_result = (tos&11100000) ^ 0b10100000;
			if(xor_result == 0){
				printf("IP       101. .... = critic/ecp\n");
			} else {
				xor_result = (tos&11100000) ^ 0b10000000;
				if(xor_result == 0){
					printf("IP       100. .... = flash override\n");
				} else {
					xor_result = (tos&11100000) ^ 0b01100000;
					if(xor_result == 0){
						printf("IP       .11. .... = flash\n");
					} else {
						xor_result = (tos&11100000) ^ 0b01000000;
						if(xor_result == 0){
							printf("IP       .10. .... = immediate\n");
						} else {
							xor_result = (tos&11100000) ^ 0b00100000;
							if(xor_result == 0){
								printf("IP       ..1. .... = priority\n");
							} else {
								printf("IP       ..0. .... = routine\n");
							}
						}
					}
				}
			}
		}
	}
	xor_result = (tos&00010000) ^ 0b00010000;
	if(xor_result == 0) printf("IP       ...1 .... = low delay\n");
	else printf("IP       ...0 .... = normal delay\n");

	xor_result = (tos&00001000) ^ 0b00001000;
	if(xor_result == 0) printf("IP       .... 1... = high throughput\n");
	else printf("IP       .... 0... = normal throughput\n");

	xor_result = (tos&00000100) ^ 0b00000100;
	if(xor_result == 0) printf("IP       .... .1.. = high reliability\n");
	else printf("IP       .... .0.. = normal reliability\n");;
}

void print_ip_flags(unsigned short flags){
	unsigned char xor_result;

	xor_result = (flags&0b010) ^ 0b010;
	if(xor_result == 0) printf("IP: .1.. .... = don't fragment\n");
	else printf("IP: .0.. .... = may fragment\n");

	xor_result = (flags&0b001) ^ 0b001;
	if(xor_result == 0) printf("IP: ..1. .... = more fragments\n");
	else printf("IP: ..0. .... = last fragment\n");
}

void print_udp_protocol(struct udp_hdr* udp, unsigned char* packet){
	unsigned char* data_start = (packet+BYTES_UNTIL_BODY+BYTES_UNTIL_IP_DATA+BYTES_UNTIL_UDP_DATA);
	printf("UDP:  ----- UDP Header -----\n");
	printf("UDP: \n");
	printf("UDP: Source port = %d\n", udp->src_port);
	printf("UDP: Destination port = %d\n", udp->dst_port);
	printf("UDP: Length = %d\n", udp->len);
	printf("UDP: Checksum = %d\n", udp->checksum);
	printf("UDP: \n");
	printf("UDP: Data: First 64 bytes\n");
	print_64_data_bytes("UDP", data_start);
	printf("UDP: \n");
}

void print_64_data_bytes(unsigned char* protocol, unsigned char* data_start){
	int i;
	for(i = 0; i < 64; i=i+2){
		if(i%16 == 0){
			if(i!=0) printf("\n");
			printf("%s: ", protocol);
		}
		printf("%02x%02x ", data_start[i], data_start[i+1]);
	}
	printf("\n");
}


void print_tcp_protocol(struct tcp_hdr* tcp_header, unsigned char* packet){
	unsigned char* data_start = (unsigned char*) (packet+BYTES_UNTIL_BODY+BYTES_UNTIL_IP_DATA+tcp_header->data_offset*4); //O data offset diz em words de 32 bits qual o tamanho da header tcp

	printf("TCP: ----- TCP Header -----\n");
	printf("TCP: Source port = %d\n", tcp_header->src_port);
	printf("TCP: Destination port = %d\n", tcp_header->dst_port);
	printf("TCP: Sequence Number = %d\n", tcp_header->seq_num);
	printf("TCP: Acknowledgement number = %d\n", tcp_header->ack_num);
	printf("TCP: Data offset = %d bytes\n", tcp_header->data_offset);
	printf("TCP: Flags = %hx\n", tcp_header->control_flags);
	print_tcp_flags(tcp_header);
	printf("TCP: Window = %d\n", tcp_header->window_size);
	printf("TCP: Checksum = %d\n", tcp_header->checksum);
	printf("TCP: Urgent pointer = %d\n", tcp_header->urgent_pointer);
	printf("TCP: No Options\n"); //DEPOIS TEM QUE VER O QUE VAI SER FEITO COM ESSE CAMPO
	printf("TCP: Data: (first 64 bytes)\n");
	print_64_data_bytes("TCP", data_start);
	printf("TCP: \n");
}

void print_tcp_flags(struct tcp_hdr* tcp_header){
	printf("           ..%d. .... = No Urgent Pointer\n", (tcp_header->control_flags & 1<<5)? 1 : 0);
	printf("           ...%d .... = Acknowledgement  \n", (tcp_header->control_flags & 1<<4)? 1 : 0);
	printf("           .... %d... = No Push          \n", (tcp_header->control_flags & 1<<3)? 1 : 0);
	printf("           .... .%d.. = No Reset         \n", (tcp_header->control_flags & 1<<2)? 1 : 0);
	printf("           .... ..%d. = No Syn           \n", (tcp_header->control_flags & 1<<1)? 1 : 0);
	printf("           .... ...%d = No Fin           \n", (tcp_header->control_flags & 1   )? 1 : 0);
}
