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

	fourth_byte = ((uint_address>>24)&0xFF);
	third_byte = ((uint_address>>16)&0xFF);
	second_byte = ((uint_address>>8)&0xFF);
	first_byte = (uint_address&0xFF);

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
	struct sockaddr_in sa;
	socklen_t len;
	char* hbuf;
	hbuf = malloc(sizeof(char)*NI_MAXHOST);
	memset(&sa, 0, sizeof(struct sockaddr_in));
	// printf("passou do memset NA translate_address"); //DEBUG

	sa.sin_family = AF_INET;
	sa.sin_addr.s_addr = inet_addr(address);
	len = sizeof(struct sockaddr_in);

	if (getnameinfo((struct sockaddr *) &sa, len, hbuf, sizeof(hbuf),
	    NULL, 0, NI_NAMEREQD)) {
	    return "Address not found";
	}
	else {
	    return hbuf;
	}
}

struct icmp_hdr* build_icmp_header(unsigned char* packet){
    struct icmp_hdr* icmp_header = (struct icmp_hdr*) (packet+BYTES_UNTIL_BODY+BYTES_UNTIL_IP_DATA);
    return icmp_header;
}

int get_packet_size(unsigned char* packet){
    return sizeof(packet);
}
