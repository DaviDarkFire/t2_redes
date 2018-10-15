#include "defines.h"
#include <time.h>

void print_current_time(){
	time_t rawtime;
  struct tm * timeinfo;

  time (&rawtime);
  timeinfo = localtime (&rawtime);
  printf ("%d:%d:%d ", timeinfo->tm_hour, timeinfo->tm_min, timeinfo->tm_sec);
}

char * get_address_as_string_from_uint(unsigned int uint_address){
	unsigned char first_byte, second_byte, third_byte, fourth_byte;
	char* char_address = malloc(sizeof(char)*15);

	first_byte = ((uint_address>>24)&0xFF);
	second_byte = ((uint_address>>16)&0xFF);
	third_byte = ((uint_address>>8)&0xFF);
	fourth_byte = (uint_address&0xFF);

	sprintf(char_address, "%d.%d.%d.%d", first_byte, second_byte, third_byte, fourth_byte);

	return char_address;
}

unsigned char* get_mac_adress(char *iface){
	int fd;
    struct ifreq ifr;
    unsigned char *mac;

    fd = socket(AF_INET, SOCK_DGRAM, 0);
    ifr.ifr_addr.sa_family = AF_INET;
    strncpy(ifr.ifr_name , iface , IFNAMSIZ-1);
    ioctl(fd, SIOCGIFHWADDR, &ifr);
    close(fd);

    mac = (unsigned char *)ifr.ifr_hwaddr.sa_data;

    return mac;
}

struct tcp_hdr* build_tcp_header(unsigned char* packet){
	struct tcp_hdr* tcp_header = (struct tcp_hdr*) (packet+BYTES_UNTIL_BODY+BYTES_UNTIL_IP_DATA);
	return tcp_header;
};

struct ip_hdr* build_ip_header(unsigned char* packet){
	struct ip_hdr* ip_header = (struct ip_hdr*) (packet+BYTES_UNTIL_BODY);
	return ip_header;
}

struct udp_hdr* build_udp_header(unsigned char* packet){
	struct udp_hdr* udp_header = (struct udp_hdr*) (packet+BYTES_UNTIL_BODY+BYTES_UNTIL_IP_DATA);
	return udp_header;
}

struct arp_hdr* build_arp_header(unsigned char* packet){
	struct arp_hdr* arp_header = (struct arp_hdr*) (packet+BYTES_UNTIL_BODY);
	return arp_header;
}

char* translate_address(char* address){
	static char hostname[65] = "";

	struct sockaddr_in sa;
	memset(&sa, 0, sizeof(sa));
	sa.sin_family = AF_INET;
	sa.sin_addr.s_addr	= inet_addr(address);
	sa.sin_port = 0;

	getnameinfo((struct sockaddr *)&sa, sizeof(sa), hostname, 64, NULL, 0, 0);

	return hostname;
}

struct icmp_hdr* build_icmp_header(unsigned char* packet){
    struct icmp_hdr* icmp_header = (struct icmp_hdr*) (packet+BYTES_UNTIL_BODY+BYTES_UNTIL_IP_DATA);
    return icmp_header;
}

int get_packet_size(unsigned char* packet){
    return sizeof(packet);
}

void printBits(size_t const size, void const * const ptr)
{
    unsigned char *b = (unsigned char*) ptr;
    unsigned char byte;
    int i, j;

    for (i=size-1;i>=0;i--)
    {
        for (j=7;j>=0;j--)
        {
            byte = (b[i] >> j) & 1;
            printf("%u", byte);
        }
    }
    puts("");
}

unsigned long int get_ulint_ether_addr_from_string(char* str_addr){
	int values[6];
	int shift_bits = 40;
	int i;
	unsigned long int ulint_addr = 0;
	unsigned long int aux;

	sscanf(str_addr, "%x:%x:%x:%x:%x:%x",
	&values[0], &values[1], &values[2],
	&values[3], &values[4], &values[5]);

	for(i = 0; i < 6; i++){
		aux = values[i];
		ulint_addr = ulint_addr | (aux << shift_bits);
		shift_bits = shift_bits-8;
	}
	return ulint_addr;
}

unsigned long int get_ulint_ip_addr_from_string(char* str_addr){
	int values[4];
	int shift_bits = 24;
	int i;
	unsigned long int ulint_addr = 0;
	unsigned long int aux;

	sscanf(str_addr, "%d.%d.%d.%d",
	&values[0], &values[1], &values[2], &values[3]);

	for(i = 0; i < 4; i++){
		aux = values[i];
		ulint_addr = ulint_addr | (aux << shift_bits);
		shift_bits = shift_bits-8;
	}
	return ulint_addr;
}

char* get_icmp_type_string(unsigned char type){
	char* type_string;
	type_string = malloc(sizeof(char)*32);
	switch(type){
		case 0:
			strcpy(type_string, "Echo reply");
		break;

		case 3:
			strcpy(type_string, "Destination unreachable");
		break;

		case 5:
			strcpy(type_string, "Redirect message");
		break;

		case 8:
			strcpy(type_string, "Echo request");
		break;

		case 9:
			strcpy(type_string, "Router advertisement");
		break;

		case 10:
			strcpy(type_string, "Router solicitation");
		break;

		case 11:
			strcpy(type_string, "Time exceeded");
		break;

		case 12:
			strcpy(type_string, "Parameter problem: bad IP header");
		break;

		case 13:
			strcpy(type_string, "Timestamp");
		break;

		case 14:
			strcpy(type_string, "Timestamp reply");
		break;

		case 42:
			strcpy(type_string, "Extended echo request");
		break;

		case 43:
			strcpy(type_string, "Extended echo reply");
		break;

		default: strcpy(type_string, "Unknown");
	}
	return type_string;
}

// Print an Ethernet address
void print_eth_address(char *s, unsigned char *eth_addr)
{
	printf("%s %02X:%02X:%02X:%02X:%02X:%02X", s,
	       eth_addr[0], eth_addr[1], eth_addr[2],
	       eth_addr[3], eth_addr[4], eth_addr[5]);
}
