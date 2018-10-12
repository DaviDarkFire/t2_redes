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
			print_ether_protocol(eth, packet_counter, get_packet_size(packet));
			print_ip_protocol(ip_header);
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
	printf("%s: %02x%02x %02x%02x %02x%02x %02x%02x %02x%02x %02x%02x %02x%02x %02x%02x\n", protocol,
	data_start[0], data_start[1], data_start[2], data_start[3], data_start[4], data_start[5], data_start[6], data_start[7],
	data_start[8], data_start[9], data_start[10], data_start[11], data_start[12], data_start[13], data_start[14], data_start[15]);
	printf("%s: %02x%02x %02x%02x %02x%02x %02x%02x %02x%02x %02x%02x %02x%02x %02x%02x\n", protocol,
	data_start[16], data_start[17], data_start[18], data_start[19], data_start[20], data_start[21], data_start[22], data_start[23],
	data_start[24], data_start[25], data_start[26], data_start[27], data_start[28], data_start[29], data_start[30], data_start[31]);
	printf("%s: %02x%02x %02x%02x %02x%02x %02x%02x %02x%02x %02x%02x %02x%02x %02x%02x\n", protocol,
	data_start[32], data_start[33], data_start[34], data_start[35], data_start[36], data_start[37], data_start[38], data_start[39],
	data_start[40], data_start[41], data_start[42], data_start[43], data_start[44], data_start[45], data_start[46], data_start[47]);
	printf("%s: %02x%02x %02x%02x %02x%02x %02x%02x %02x%02x %02x%02x %02x%02x %02x%02x\n", protocol,
	data_start[48], data_start[49], data_start[50], data_start[51], data_start[52], data_start[53], data_start[54], data_start[55],
	data_start[56], data_start[57], data_start[58], data_start[59], data_start[60], data_start[61], data_start[62], data_start[63]);
}
