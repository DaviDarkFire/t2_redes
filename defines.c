#define MAX_PACKET_SIZE 65536
#define MIN_PACKET_SIZE 64
#define BYTES_UNTIL_BODY 14

/* */
struct ether_hdr {
	unsigned char	ether_dhost[6];	// Destination address
	unsigned char	ether_shost[6];	// Source address
	unsigned short	ether_type;	// Type of the payload
};
/* */
struct ip_hdr {
	unsigned char 	ip_v:4,		// IP Version
			ip_hl:4;	// Header length
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