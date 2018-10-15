#include "defines.h"
#include "struct_dealer.h"
#include "verbose_mode.h"
#include "ext_verbose_mode.h"
#include "misc.h"

// headers
void flag_setter();
void basic_mode(struct ether_hdr* eth, unsigned char* packet, struct options* opt);
int bind_iface_name(int fd, char *iface_name);
void print_eth_address(char *s, unsigned char *eth_addr);
struct ip_hdr* build_ip_header(unsigned char* packet);
void do_process(unsigned char* packet, int len, struct options* opt, char** filters, unsigned int filters_len);
void print_usage();
// end of headers

volatile sig_atomic_t flag = 0;
void flag_setter(){
	flag = 1;
}

void basic_mode(struct ether_hdr* eth, unsigned char* packet, struct options* opt){
  static struct statistics stat;

  if(flag == 1){
    print_statistics(&stat);
    printf("END OF EXECUTION\n");
    exit(0);
  }

  stat.ethernet_frames += 1;

	int n_of_ffs = 0;
	int i;

	for(i = 0; i < 6; i++){
		if(eth->ether_dhost[i] == 0xff) n_of_ffs++;
	}

	if(n_of_ffs == 6){
		stat.ethernet_broadcast++;
	}else{
		if(memcmp(get_mac_adress(opt->iface), eth->ether_dhost, 6) == 0)
    		stat.to_this_host++;
		 }

	if(eth->ether_type == htons(0x0800)) { //IP
		stat.ip++;
		struct ip_hdr* ip_header;
		ip_header = build_ip_header(packet);
		if(ip_header->ip_proto == ICMP) stat.icmp++; // IP-ICMP
		else if(ip_header->ip_proto == UDP) stat.udp++; // IP-UDP
		else if(ip_header->ip_proto == TCP) stat.tcp++; // IP-TCP
	} else if(eth->ether_type == htons(0x0806)) { // ARP
		stat.arp++;
	}
}

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



/* */
// Break this function to implement the functionalities of your packet analyser
void do_process(unsigned char* packet, int len, struct options* opt, char** filters, unsigned int filters_len) {
  // printf("entrei na do_process\n"); //DEBUG
	if(!len || len < MIN_PACKET_SIZE)
		return;

	struct ether_hdr* eth = (struct ether_hdr*) packet;

  if(opt->mode == BASIC_MODE){
    // printf("Entrou no if basic mode\n"); //DEBUG
		printf("Capturing packets... Ctrl+C to exit. \n");
    	basic_mode(eth, packet, opt);
  } else if(opt->mode == VERBOSE_MODE){
  	verbose_mode(eth, packet, opt);

  } else if(opt->mode == EXTENDED_VERBOSE_MODE){
  	extended_verbose_mode(eth, packet, opt, filters, filters_len);
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

// BEGINNING: dealing with user's parameters in command line
	if (argc < 3)
		print_usage();

	if (strcmp(argv[1], "-i"))
		print_usage();

	struct options* opt;
	opt = malloc(sizeof(struct options));
    init_options(opt);
	int start_filters_pos = 0;
	start_filters_pos = set_options(opt, argc, argv)+1;

	unsigned int filters_len = argc-start_filters_pos;
	char** filters = argv+start_filters_pos;

	// END: dealing with user's parameters in command line

  if(opt->mode == BASIC_MODE){
    struct sigaction act;
    act.sa_handler = &flag_setter;
    act.sa_flags = SA_RESTART | SA_NOCLDSTOP;
    sigemptyset (&act.sa_mask);

    if (sigaction(SIGINT, &act, NULL) == -1) {
	  	perror(0);
	  	exit(1);
    }

  }

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
		do_process(packet_buffer, n, opt, filters, filters_len);
	}

	free(packet_buffer);
	close(sockfd);

	return 0;
}
/* */
