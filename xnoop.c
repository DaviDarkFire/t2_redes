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
#include "defines.c"
/* */
/* */



// Bind a socket to a interface
int bind_iface_name(int fd, char *iface_name)
{
	return setsockopt(fd, SOL_SOCKET, SO_BINDTODEVICE, iface_name, strlen(iface_name));
}
/* */
// Print an Ethernet address
void print_eth_address(char *s, unsigned char *eth_addr)
{
	printf("%s %02X:%02X:%02X:%02X:%02X:%02X", s,
	       eth_addr[0], eth_addr[1], eth_addr[2],
	       eth_addr[3], eth_addr[4], eth_addr[5]);
}

void build_ip_header(unsigned char* buffer, int len){
	struct ip_hdr* ip_header = (struct ip_hdr*) buffer+BYTES_UNTIL_BODY;
	printf("\nIP src address = 0x%hx\n", ntohs(ip_header->ip_src));//DEBUG
	printf("\nIP dest address = 0x%hx\n", ntohs(ip_header->ip_dst));//DEBUG
	// print_eth_address("IP src ADRESS", ntohs(ip_header->ip_src)); //DEBUG
	// print_eth_address("IP dest ADRESS", ntohs(ip_header->ip_dst)); //DEBUG
	// printf("\n");
	// for(int i = 0; i < len; i++)	{
	// 	printf("%3X", buffer[i]);

	// }
	printf("\nsizeof: %d\n", sizeof(ip_header->ip_src));

        
     printf("\n");

}

/* */
// Break this function to implement the functionalities of your packet analyser
void do_process(unsigned char* packet, int len) {
	if(!len || len < MIN_PACKET_SIZE)
		return;

	struct ether_hdr* eth = (struct ether_hdr*) packet;

	print_eth_address("\nDst =", eth->ether_dhost);
	print_eth_address(" Src =", eth->ether_shost);
	printf(" Ether Type = 0x%04X Size = %d", ntohs(eth->ether_type), len);

	build_ip_header(packet, len);


	
	if(eth->ether_type == htons(0x0800)) {
		//IP

		//...
	} else if(eth->ether_type == htons(0x0806)) {
		//ARP
		
		//...
	}
	fflush(stdout);
}
/* */
// Print the expected command line for the program
void print_usage()
{
	printf("\nxnoop -i <interface> [options] [filter]\n");
	exit(1);
}
/* */
// main function
int main(int argc, char** argv) {
	int		n;
	int		sockfd;
	socklen_t	saddr_len;
	struct sockaddr	saddr;
	unsigned char	*packet_buffer;

	if (argc < 3)
		print_usage();
	
	if (strcmp(argv[1], "-i"))
		print_usage();	
	
	saddr_len = sizeof(saddr);
	sockfd = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL));  
	if(sockfd < 0) {
		fprintf(stderr, "ERROR: %s\n", strerror(errno));
		exit(1);
	}
	
	if (bind_iface_name(sockfd, argv[2]) < 0) {
		perror("Server-setsockopt() error for SO_BINDTODEVICE");
		printf("%s\n", strerror(errno));
		close(sockfd);
		exit(1);
	}

	packet_buffer = malloc(MAX_PACKET_SIZE);
	if (!packet_buffer) {
		printf("\nCould not allocate a packet buffer\n");		
		exit(1);
	}
	
	while(1) {
		n = recvfrom(sockfd, packet_buffer, MAX_PACKET_SIZE, 0, &saddr, &saddr_len);
		if(n < 0) {
			fprintf(stderr, "ERROR: %s\n", strerror(errno));
			exit(1);
		}
		do_process(packet_buffer, n);
	}

	free(packet_buffer);
	close(sockfd);

	return 0;
}
/* */
