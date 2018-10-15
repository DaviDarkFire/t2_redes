#include "defines.h"
#include "misc.h"
#include "ext_verbose_mode.h"
#include "stack.h"

void extended_verbose_mode(struct ether_hdr* eth, unsigned char* packet, struct options* opt, char** filters, unsigned int filters_len){
	static int packet_counter = 0;

	if(packet_counter == opt->show_n_first_packets)
		exit(0);

	if (filters_len > 0){
		struct stack_node* root = NULL;
		compute_stack(packet, &root ,filters, filters_len);
		if (peek(root) == 0) return;

	}


	packet_counter++;

	print_ether_protocol(eth, packet_counter, get_packet_size(packet));

	if(eth->ether_type == htons(0x0800)) { //IP
		struct ip_hdr* ip_header;
		ip_header = build_ip_header(packet);

		print_ip_protocol(ip_header, opt->shouldnt_translate_names);

		if(ip_header->ip_proto == ICMP){ // IP-ICMP
			struct icmp_hdr* icmp_header;
			icmp_header = build_icmp_header(packet);
			print_icmp_protocol(icmp_header);
		}
		else if(ip_header->ip_proto == UDP){ // IP-UDP
			struct udp_hdr* udp_header;
			udp_header = build_udp_header(packet);
			print_udp_protocol(udp_header, packet);
		}
		else if(ip_header->ip_proto == TCP){ // IP-TCP
			struct tcp_hdr* tcp_header =  build_tcp_header(packet);
			print_tcp_protocol(tcp_header, packet);
		}
		else { // IP-UNKNOWN protocol
			printf("This analyzer doesn't know this packet's protocol.\n\n");
		}
	} else if(eth->ether_type == htons(0x0806)) { // ARP
		struct arp_hdr* arp_header;
		arp_header = build_arp_header(packet);
		print_arp_protocol(arp_header);
	} else {
		printf("This analyzer doesn't know this packet's protocol.\n\n");
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
	printf("ETHER: Packet size = %u bytes\n", packet_size);
	printf("ETHER: Destination = %02X:%02X:%02X:%02X:%02X:%02X,\n",
	 eth->ether_dhost[0], eth->ether_dhost[1], eth->ether_dhost[2],eth->ether_dhost[3], eth->ether_dhost[4], eth->ether_dhost[5]);
	printf("ETHER: Source      = %02X:%02X:%02X:%02X:%02X:%02X,\n",
	 eth->ether_shost[0], eth->ether_shost[1], eth->ether_shost[2],eth->ether_shost[3], eth->ether_shost[4], eth->ether_shost[5]);
	printf("ETHER: Ethertype   = %u (%s)\n",  eth->ether_type, protocol);
	printf("ETHER: \n");
}

void print_ip_protocol(struct ip_hdr* ip, int shouldnt_translate){
	char protocol[4];

	char* src_addr = get_address_as_string_from_uint(ntohl(ip->ip_src));
	char* dst_addr = get_address_as_string_from_uint(ntohl(ip->ip_dst));


	if(ip->ip_proto == TCP)
		strcpy(protocol,"TCP");
	else if(ip->ip_proto == UDP)
		strcpy(protocol, "UDP");
		else if(ip->ip_proto == ICMP)
			strcpy(protocol, "ICMP");
			else
				strcpy(protocol, "UNKNOWN");

	printf("IP:   ----- IP Header -----\n");
	printf("IP:   \n");
	printf("IP:   Version = %u, header length = %u bytes\n", ip->ip_v, ip->ip_hl);
	printf("IP:   Type of service = %2u\n", ip->ip_tos);
	print_ip_tos(ip->ip_tos);
	printf("IP:   Total length = %u bytes\n", ntohs(ip->ip_len));
	printf("IP:   Identification = %u\n", ntohs(ip->ip_id));
	printf("IP:   Flags = 0x%x\n", ip->ip_flags);
	print_ip_flags(ip->ip_flags);
	printf("IP:   Fragment offset = %u bytes\n", ip->ip_offset);
	printf("IP:   Time to live = %u seconds/hops\n", ip->ip_ttl);
	printf("IP:   Protocol = %u (%s)\n", ip->ip_proto, protocol);
	printf("IP:   Header checksum = %4x\n", ntohs(ip->ip_csum));

	printf("IP:   Source address = %s", src_addr);
	if(shouldnt_translate == DONT_USE_OPTION){
		char* t_src_addr = translate_address(src_addr);

		if ((t_src_addr[3] == '.' || t_src_addr[2] == '.' || t_src_addr[1] == '.')
		 && isdigit(t_src_addr[0]))
			printf("\n"); // don't print the address unless it's actually translated
		else printf(", %s\n", t_src_addr);
	}
	else{
		printf("\n");
	}

	printf("IP:   Destination address = %s", dst_addr);
	if(shouldnt_translate == DONT_USE_OPTION){
		char* t_dst_addr = translate_address(dst_addr);

		if ((t_dst_addr[3] == '.' || t_dst_addr[2] == '.' || t_dst_addr[1] == '.')
		 && isdigit(t_dst_addr[0]))
			printf("\n"); // don't print the address unless it's actually translated
		else printf(", %s\n", t_dst_addr);
			printf("IP:   \n");
	}
	else{
		printf("\n");
	}
	printf("IP:   \n");

	free(src_addr);
	free(dst_addr);
}

void print_ip_tos(unsigned char tos){
	unsigned int xor_result;

	xor_result = (tos&11100000) ^ 0b11100000;
	if(xor_result == 0){
		printf("IP:       111. .... = network control\n");
	} else {
		xor_result = (tos&11100000) ^ 0b11000000;
		if(xor_result == 0){
			printf("IP:       110. .... = internetwork control\n");
		} else {
			xor_result = (tos&11100000) ^ 0b10100000;
			if(xor_result == 0){
				printf("IP:       101. .... = critic/ecp\n");
			} else {
				xor_result = (tos&11100000) ^ 0b10000000;
				if(xor_result == 0){
					printf("IP:       100. .... = flash override\n");
				} else {
					xor_result = (tos&11100000) ^ 0b01100000;
					if(xor_result == 0){
						printf("IP:       .11. .... = flash\n");
					} else {
						xor_result = (tos&11100000) ^ 0b01000000;
						if(xor_result == 0){
							printf("IP:       .10. .... = immediate\n");
						} else {
							xor_result = (tos&11100000) ^ 0b00100000;
							if(xor_result == 0){
								printf("IP:       ..1. .... = priority\n");
							} else {
								printf("IP:       ..0. .... = routine\n");
							}
						}
					}
				}
			}
		}
	}

	xor_result = (tos&00010000) ^ 0b00010000;
	if(xor_result == 0) printf("IP:       ...1 .... = low delay\n");
	else printf("IP:       ...0 .... = normal delay\n");

	xor_result = (tos&00001000) ^ 0b00001000;
	if(xor_result == 0) printf("IP:       .... 1... = high throughput\n");
	else printf("IP:       .... 0... = normal throughput\n");

	xor_result = (tos&00000100) ^ 0b00000100;
	if(xor_result == 0) printf("IP:       .... .1.. = high reliability\n");
	else printf("IP:       .... .0.. = normal reliability\n");;
}

void print_ip_flags(unsigned short flags){
	unsigned char xor_result;

	xor_result = (flags&0b010) ^ 0b010;
	if(xor_result == 0) printf("IP:       .1.. .... = do not fragment\n");
	else printf("IP:       .0.. .... = may fragment\n");

	xor_result = (flags&0b001) ^ 0b001;
	if(xor_result == 0) printf("IP:       ..1. .... = more fragments\n");
	else printf("IP:       ..0. .... = last fragment\n");
}

void print_udp_protocol(struct udp_hdr* udp, unsigned char* packet){
	unsigned char* data_start = (packet+BYTES_UNTIL_BODY+BYTES_UNTIL_IP_DATA+BYTES_UNTIL_UDP_DATA);
	printf("UDP:  ----- UDP Header -----\n");
	printf("UDP:  \n");
	printf("UDP:  Source port = %u\n", ntohs(udp->src_port));
	printf("UDP:  Destination port = %u\n", ntohs(udp->dst_port));
	printf("UDP:  Length = %u\n", ntohs(udp->len));
	printf("UDP:  Checksum = %4x\n", ntohs(udp->checksum));
	printf("UDP:  \n");
	printf("UDP: Data: First 64 bytes\n");
	print_64_data_bytes("UDP", data_start);
	printf("UDP: \n\n");
}

void print_64_data_bytes(unsigned char* protocol, unsigned char* data_start){
	int i;
	char ascii_buffer[16];

	for(i = 0; i < 64; i=i+2){
		if(i%16 == 0){
			if(i!=0) printf(" \"%s\"\n", ascii_buffer);
			printf("%s: ", protocol);
		}
		printf("%02x%02x ", data_start[i], data_start[i+1]);
		if(data_start[i] >= 32 && data_start[i] <= 126)
			ascii_buffer[i%16] = data_start[i];
		else
			ascii_buffer[i%16] = '.';

		if(data_start[i+1] >= 32 && data_start[i+1] <= 126)
		ascii_buffer[(i+1)%16] = data_start[i+1];
		else
			ascii_buffer[(i+1)%16] = '.';
	}
	printf(" \"%s\"\n", ascii_buffer);
}


void print_tcp_protocol(struct tcp_hdr* tcp_header, unsigned char* packet){
	unsigned char* data_start = (unsigned char*) (packet+BYTES_UNTIL_BODY+BYTES_UNTIL_IP_DATA+tcp_header->data_offset*4); //O data offset diz em words de 32 bits qual o tamanho da header tcp

	printf("TCP:  ----- TCP Header -----\n");
	printf("TCP:  Source port = %u\n", ntohs(tcp_header->src_port));
	printf("TCP:  Destination port = %u\n", ntohs(tcp_header->dst_port));
	printf("TCP:  Sequence Number = %u\n", ntohl(tcp_header->seq_num));
	printf("TCP:  Acknowledgement number = %u\n", ntohl(tcp_header->ack_num));
	printf("TCP:  Data offset = %u bytes\n", tcp_header->data_offset);
	printf("TCP:  Flags = 0x%hx\n", tcp_header->control_flags);
	print_tcp_flags(tcp_header);
	printf("TCP:  Window = %u\n", ntohs(tcp_header->window_size));
	printf("TCP:  Checksum = %4x\n", ntohs(tcp_header->checksum));
	printf("TCP:  Urgent pointer = %u\n", ntohs(tcp_header->urgent_pointer));
	printf("TCP:  No Options\n");
	printf("TCP: Data: (first 64 bytes)\n");
	print_64_data_bytes("TCP", data_start);
	printf("TCP: \n\n");
}

void print_tcp_flags(struct tcp_hdr* tcp_header){
	if(tcp_header->control_flags & 1<<5) printf("           ..1. .... = Urgent Pointer\n");
	else printf("           ..0. .... = No Urgent Pointer\n");

	if(tcp_header->control_flags & 1<<4) printf("           ...1 .... = Acknowledgement  \n");
	else printf("           ...0 .... = No Acknowledgement  \n");

	if(tcp_header->control_flags & 1<<3) printf("           .... 1... = Push          \n");
	else printf("           .... 0... = No Push          \n");

	if(tcp_header->control_flags & 1<<2) printf("           .... .1.. = Reset         \n");
	else printf("           .... .0.. = No Reset         \n");

	if(tcp_header->control_flags & 1<<1) printf("           .... ..1. = Syn           \n");
	else printf("           .... ..0. = No Syn           \n");

	if(tcp_header->control_flags & 1) printf("           .... ...1 = Fin           \n");
	else printf("           .... ...0 = No Fin           \n");
}

void print_icmp_protocol(struct icmp_hdr* icmp){
	char* type_string;
	type_string = get_icmp_type_string(icmp->type);
	printf("ICMP:  ----- ICMP Header -----\n");
	printf("ICMP:  \n");
	printf("ICMP:  Type = %u (%s)\n", icmp->type, type_string);
	printf("ICMP:  Code = %u\n", icmp->code);
	printf("ICMP:  Checksum = %4x\n", ntohs(icmp->checksum));
	printf("ICMP:  \n\n");
	free(type_string);
}



void print_arp_protocol(struct arp_hdr* arp){
	char* sdr_hw_addr;
	sprintf(sdr_hw_addr, "%x:%x:%x:%x:%x:%x",
	 arp->sender_hw_addr[5], arp->sender_hw_addr[4], arp->sender_hw_addr[3],
	 arp->sender_hw_addr[2], arp->sender_hw_addr[1], arp->sender_hw_addr[0]);
	char* sdr_pt_addr = get_address_as_string_from_uint(ntohl(arp->sender_proto_addr));
	char* tgt_hw_addr;
	sprintf(sdr_hw_addr, "%x:%x:%x:%x:%x:%x",
	 arp->target_hw_addr[5], arp->target_hw_addr[4], arp->target_hw_addr[3],
	 arp->target_hw_addr[2], arp->target_hw_addr[1], arp->target_hw_addr[0]);
	char* tgt_pt_addr = get_address_as_string_from_uint(ntohl(arp->target_proto_addr));

	printf("ARP:  ----- ARP/RARP Frame -----\n");
	printf("ARP:  \n");
	printf("ARP:  Hardware type = %u\n", ntohs(arp->hardware_type));
	printf("ARP:  Protocol type = %u\n", ntohs(arp->protocol_type));
	printf("ARP:  Length of hardware address = %u bytes\n", arp->hw_addr_len);
	printf("ARP:  Length of protocol address = %u bytes\n", arp->proto_addr_len);
	printf("ARP:  Opcode %u\n", ntohs(arp->opcode));
	printf("ARP:  Sender's hardware address = %s\n", sdr_hw_addr);
	printf("ARP:  Sender's protocol address = %s\n", sdr_pt_addr);
	printf("ARP:  Target hardware address = %s\n", tgt_hw_addr);
	printf("ARP:  Target protocol address = %s\n", tgt_pt_addr);
	printf("ARP:  \n\n");

	free(sdr_hw_addr);
	free(sdr_pt_addr);
	free(tgt_hw_addr);
	free(tgt_pt_addr);
}
