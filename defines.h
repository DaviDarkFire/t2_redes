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
#include <sys/ioctl.h>
#include <net/if.h>


#define MAX_PACKET_SIZE 65536
#define MIN_PACKET_SIZE 64
#define BYTES_UNTIL_BODY 14
#define BYTES_UNTIL_IP_DATA 20
#define DONT_USE_OPTION -1

#define BASIC_MODE 0
#define VERBOSE_MODE 1
#define EXTENDED_VERBOSE_MODE 2

#define ICMP 0x01
#define UDP 0x11
#define TCP 0x06

/* */
struct ether_hdr {
	unsigned char	ether_dhost[6];	// Destination address
	unsigned char	ether_shost[6];	// Source address
	unsigned short	ether_type;	// Type of the payload
};
/* */
struct ip_hdr {
#if __BYTE_ORDER__ == __ORDER_LITTLE_ENDIAN__
	unsigned char ip_hl:4,
								ip_v:4;
#elif __BYTE_ORDER__ == __ORDER_BIG_ENDIAN__
	unsigned char ip_v:4,
								ip_hl:4;
#endif

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

struct tcp_hdr {
	unsigned short src_port;
	unsigned short dst_port;
	unsigned int seq_num;
	unsigned int ack_num;
	// TODO: talvez tenha que fazer esquema do bigendian x lil endian aqui
	unsigned short data_offset:4, reserved:3, control_flags: 9;
	unsigned short window_size;
	unsigned short checksum;
	unsigned short urgent_pointer;
	// options?
};

struct udp_hdr {
	unsigned short src_port;
	unsigned short dst_port;
	unsigned short len;
	unsigned short checksum;
};

struct arp_hdr {
	unsigned short hardware_type;
	unsigned short protocol_type;
	unsigned char hw_addr_len;
	unsigned char proto_addr_len;
	unsigned short opcode;
	unsigned short sender_hw_addr;
	unsigned int sender_proto_addr;
	unsigned int target_hw_addr;
	unsigned int target_proto_addr;
};

struct icmp_hdr {
	unsigned char type;
	unsigned char code;
	unsigned short checksum;

	// unsigned short src_port;
	// unsigned short dst_port;
	// unsigned int seq_num;
	// unsigned int ack_num;
	// // talvez tenha que fazer esquema do bigendian x lil endian aqui
	// unsigned short data_offset:4, reserved:3, control_flags: 9;
	// unsigned short window_size;
	// unsigned short checksum;
	// unsigned short urgent_pointer;
	// options?
};

struct options {
	char* iface;
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
