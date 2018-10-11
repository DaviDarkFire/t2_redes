#include "defines.h"
#include "misc.h"


void print_ip_packet_verbose(unsigned char* packet, struct ip_hdr* ip_header, int shouldnt_translate){
	print_current_time();
	// printf("passou da print current time\n");// DEBUG

	char* src_address = get_address_as_string_from_uint(ip_header->ip_src);
	char* dst_address = get_address_as_string_from_uint(ip_header->ip_dst);

		// printf("passou das get_address_as_string_from_uint\n");// DEBUG

	if(shouldnt_translate == DONT_USE_OPTION){ // translate addresses
		char* translated_src = translate_address(src_address);
		printf(" %s ", translated_src);
		free(translated_src);

		char* translated_dst = translate_address(dst_address);
		printf(" %s ", translated_dst);
		free(translated_dst);

			// printf("passou das translate_address\n");// DEBUG

	} else { // don't translate addresses

		printf(" %s ", src_address);
		printf("->");
		printf(" %s ", dst_address);
	}
	free(src_address);
	free(dst_address);

	// TODO: printar aplicação aqui
	if(ip_header->ip_proto == TCP){
		printf("TCP ");
		struct tcp_hdr* tcp_header = build_tcp_header(packet);
		printf("sourceport=%d ", tcp_header->src_port);
		printf("destport=%d\n", tcp_header->dst_port);
	} else if (ip_header->ip_proto == UDP){
		printf("UDP ");
		struct udp_hdr* udp_header = build_udp_header(packet);
		printf("sourceport=%d ", udp_header->src_port);
		printf("destport=%d\n", udp_header->dst_port);
	} else if (ip_header->ip_proto == ICMP){
		printf("ICMP ");
		// struct icmp_hdr* icmp_header = build_icmp_header(packet);
		printf("Destination unreachable (Bad port)\n");
	}

	// cada protocolo terá seu if com os prints do nome do protocolo e das portas
}

void print_arp_packet_verbose(unsigned char* packet, int shouldnt_translate){

}

void verbose_mode(struct ether_hdr* eth, unsigned char* packet, struct options* opt){
	static int packet_counter = 0;

	if(packet_counter == opt->show_n_first_packets)
		exit(0);

	packet_counter++;
	// printf("Total: %d Current: %d\n", opt->show_n_first_packets, packet_counter); //DEBUG

	if(eth->ether_type == htons(0x0800)) { //IP
		struct ip_hdr* ip_header;
		ip_header = build_ip_header(packet);
		if(ip_header->ip_proto == ICMP){ // IP-ICMP
			// printf("This is an ICMP Packet.\n");// DEBUG
			print_ip_packet_verbose(packet, ip_header, opt->shouldnt_translate_names);
		}
		else if(ip_header->ip_proto == UDP){ // IP-UDP
			// printf("This is an UDP Packet.\n");// DEBUG
			print_ip_packet_verbose(packet, ip_header, opt->shouldnt_translate_names);
		}
		else if(ip_header->ip_proto == TCP){ // IP-TCP
			// printf("This is a TCP Packet.\n");// DEBUG
			print_ip_packet_verbose(packet, ip_header, opt->shouldnt_translate_names);
		}
		else {
			// printf("This analyzer doesn't know this packet's protocol.\n");
		}
	} else if(eth->ether_type == htons(0x0806)) { // ARP
		// printf("This is an ARP Packet.\n");// DEBUG
	} else {
		// printf("This analyzer doesn't know this packet's protocol.\n");
	}
}
