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
			print_udp_protocol(udp_header);
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
	// unsigned char bits bits_zero_to_two, bit_three, bit_four, bit_five;
	// bits_zero_to_two = ((tos>>5)&0xFF);
	// bit_three = ((tos>>4)&0xFF);
	// bit_four =  ((tos>>3)&0xFF);
	// bit_five = ((tos>>2)&0xFF);

	printf("IP:       .... .... = lorem ipsum\n"); // TOS descrito
	printf("IP:       .... .... = lorem ipsum\n"); // TOS descrito
	printf("IP:       .... .... = lorem ipsum\n"); // TOS descrito
	printf("IP:       .... .... = lorem ipsum\n"); // TOS descrito
	// if(bits_zero_to_two == )
}

void print_ip_flags(unsigned short flags){
	printf("IP: .... .... = lorem ipsum\n"); // flags descritas
	printf("IP: .... .... = lorem ipsum\n"); // flags descritas
}

void print_udp_protocol(struct udp_hdr* udp){
	printf("UDP:  ----- UDP Header -----\n");
	printf("UDP: \n");
	printf("UDP: Source port = %d\n", udp->src_port);
	printf("UDP: Destination port = %d\n", udp->dst_port);
	printf("UDP: Length = %d\n", udp->len);
	printf("UDP: Checksum = %d\n", udp->checksum);
	printf("UDP: \n");
	printf("UDP: Data: First 64 bytes\n");
	// printf("UDP: %4x %4x %4x %4x %4x %4x %4x %4x\n", );
	// printf("UDP: %4x %4x %4x %4x %4x %4x %4x %4x\n");
	// printf("UDP: %4x %4x %4x %4x %4x %4x %4x %4x\n");
	// printf("UDP: %4x %4x %4x %4x %4x %4x %4x %4x\n");
	printf("UDP: \n");
}
