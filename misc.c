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

struct ip_hdr* build_ip_header(unsigned char* packet){
	struct ip_hdr* ip_header = (struct ip_hdr*) (packet+BYTES_UNTIL_BODY);
	return ip_header;
}
