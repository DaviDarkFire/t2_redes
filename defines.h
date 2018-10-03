#ifndef __DEFINES
	#define __DEFINES__

#include <errno.h>
#include <stdio.h>
#include <netdb.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <sys/types.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <net/ethernet.h>
#include <signal.h>



#define MAX_PACKET_SIZE 65536
#define MIN_PACKET_SIZE 64
#define BYTES_UNTIL_BODY 14
#define DONT_USE_OPTION -1

#define BASIC_MODE 0
#define VERBOSE_MODE 1
#define EXTENDED_VERBOSE_MODE 2

/* */
struct ether_hdr {
	unsigned char	ether_dhost[6];	// Destination address
	unsigned char	ether_shost[6];	// Source address
	unsigned short	ether_type;	// Type of the payload
};
/* */
struct ip_hdr {
	unsigned char ip_hl:4, // Header length NOTA: ESSA SEQUENCIA FUNCIONA PARA ESSE PC, EM OUTROS PODE NÂO FUNCIONAR DADO O BYTEORDER
	ip_v:4; //ip version

	unsigned char	ip_tos;		// Type of service
	unsigned short	ip_len;		// Datagram Length
	unsigned short	ip_id;		// Datagram identifier
	//pulou 3 bits de flag
	unsigned short	ip_offset;	// Fragment offset
	unsigned char	ip_ttl;		// Time To Live
	unsigned char	ip_proto;	// Protocol
	unsigned short	ip_csum;	// Header checksum
	unsigned int	ip_src;		// Source IP address
	unsigned int	ip_dst;		// Destination IP address
};

struct options {
	int mode;
	int show_n_first_packets;
	int shouldnt_translate_names;
};

struct statistics {
	unsigned int ethernet_frames;
	unsigned int ethernet_broadcast;
	unsigned int arp;
	unsigned int ip;
	unsigned int icmp;
	unsigned int udp;
	unsigned int tcp;
	unsigned int to_this_host;
};

#endif
