#include "defines.h"
#include "misc.h"


void print_ip_packet_verbose(unsigned char* packet, struct ip_hdr* ip_header, int shouldnt_translate){
	print_current_time();

	char* src_address = get_address_as_string_from_uint(ntohl(ip_header->ip_src));
	char* dst_address = get_address_as_string_from_uint(ntohl(ip_header->ip_dst));

	if(shouldnt_translate == DONT_USE_OPTION){ // translate addresses
		char* translated_src = translate_address(src_address);
		printf(" %s ", translated_src);
		printf("->");
		char* translated_dst = translate_address(dst_address);
		printf(" %s ", translated_dst);

	} else { // don't translate addresses

		printf(" %s ", src_address);
		printf("->");
		printf(" %s ", dst_address);
	}
	free(src_address);
	free(dst_address);

	if(ip_header->ip_proto == TCP){
		struct tcp_hdr* tcp_header = build_tcp_header(packet);
		struct servent *sptr;

		sptr = getservbyport(tcp_header->src_port, "tcp");

		printf("TCP ");
		if(sptr!=NULL) printf("%s ", sptr->s_name);
		printf("sourceport=%d ", ntohs(tcp_header->src_port));
		printf("destport=%d\n", ntohs(tcp_header->dst_port));

	} else if (ip_header->ip_proto == UDP){
		struct udp_hdr* udp_header = build_udp_header(packet);
		struct servent *sptr;

		sptr = getservbyport(udp_header->src_port, "udp");

		printf("UDP ");
		if(sptr!=NULL) printf("%s ", sptr->s_name);
		printf("sourceport=%d ", ntohs(udp_header->src_port));
		printf("destport=%d\n", ntohs(udp_header->dst_port));
	} else if (ip_header->ip_proto == ICMP){
		printf("ICMP ");
		struct icmp_hdr* icmp_header = build_icmp_header(packet);
		char* type_string = get_icmp_type_string(icmp_header->type);
		printf("%s\n", type_string);
		free(type_string);
	}

}

void print_arp_packet_verbose(unsigned char* packet, int shouldnt_translate){
	struct arp_hdr* arp_header = (struct arp_hdr*) (packet+BYTES_UNTIL_BODY);
	char* src_address = get_address_as_string_from_uint(ntohl(arp_header->sender_proto_addr));
	char* dst_address = "255.255.255.255";

	print_current_time();

	if(shouldnt_translate == DONT_USE_OPTION){ // translate addresses
		char* translated_src = translate_address(src_address);
		printf(" %s ", translated_src);
		printf("->");
		char* translated_dst = translate_address(dst_address);
		printf(" %s ", translated_dst);

	} else { // don't translate addresses

		printf(" %s ", src_address);
		printf("->");
		printf(" %s ", dst_address);
	}
	free(src_address);
	free(dst_address);

	if(ntohs(arp_header->opcode) == ARP_REQUEST){
		char* target_addr = get_address_as_string_from_uint(ntohl(arp_header->target_proto_addr));
		printf("Who is %s", target_addr);
		free (target_addr);
		printf("\n");
	} else if (ntohs(arp_header->opcode) == ARP_RESPONSE){
		printf("I'm not really sure who this is");
		printf("\n");
	}
}

void verbose_mode(struct ether_hdr* eth, unsigned char* packet, struct options* opt, char** filters, unsigned int filters_len){
	static int packet_counter = 0;

	if(packet_counter == opt->show_n_first_packets)
		exit(0);

	if (filters_len > 0){
		struct stack_node* root = NULL;			compute_stack(packet, &root ,filters, filters_len);
		if (peek(root) == 0) return;

	}


	packet_counter++;

	if(eth->ether_type == htons(0x0800)) { //IP
		struct ip_hdr* ip_header;
		ip_header = build_ip_header(packet);
		if(ip_header->ip_proto == ICMP || ip_header->ip_proto == UDP || ip_header->ip_proto == TCP){
			print_ip_packet_verbose(packet, ip_header, opt->shouldnt_translate_names);
		} else {
			printf("This analyzer doesn't know this packet's protocol.\n");
		}
	} else if(eth->ether_type == htons(0x0806)) { // ARP
		print_arp_packet_verbose(packet, opt->shouldnt_translate_names);
	} else {
		printf("This analyzer doesn't know this packet's protocol.\n");
	}
}
