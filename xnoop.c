#include "defines.h"
#include "struct_dealer.h"

// headers
void flag_setter();
void basic_mode(struct ether_hdr* eth, unsigned char* packet, struct options* opt);
unsigned char* get_mac_adress(char *iface);
int bind_iface_name(int fd, char *iface_name);
void print_eth_address(char *s, unsigned char *eth_addr);
struct ip_hdr* build_ip_header(unsigned char* packet);
void do_process(unsigned char* packet, int len, struct options* opt);
void print_usage();
void verbose_mode(struct ether_hdr* eth, unsigned char* packet, struct options* opt);
void extended_verbose_mode(struct ether_hdr* eth, unsigned char* packet, struct options* opt);

// end of headers


void verbose_mode(struct ether_hdr* eth, unsigned char* packet, struct options* opt){
	static int packet_counter = 0;

	if(packet_counter == opt->show_n_first_packets)
		exit(0);

	packet_counter++;
	// printf("Total: %d Current: %d\n", opt->show_n_first_packets, packet_counter); //DEBUG

	if(eth->ether_type == htons(0x0800)) { //IP
		struct ip_hdr* ip_header;
		ip_header = build_ip_header(packet);
		if(ip_header->ip_proto == ICMP){ // IP-ICMP
			printf("This is an ICMP Packet.\n");// DEBUG
		} 
		else if(ip_header->ip_proto == UDP){ // IP-UDP
			printf("This is an UDP Packet.\n");// DEBUG
		} 
		else if(ip_header->ip_proto == TCP){ // IP-TCP
			printf("This is a TCP Packet.\n");// DEBUG
		} 
		else {
			printf("This analyzer doesn't know this packet's protocol.\n");
		}
	} else if(eth->ether_type == htons(0x0806)) { // ARP
		printf("This is an ARP Packet.\n");// DEBUG
	} else {
		printf("This analyzer doesn't know this packet's protocol.\n");
	}
}

void extended_verbose_mode(struct ether_hdr* eth, unsigned char* packet, struct options* opt){
	static int packet_counter = 0;

	if(packet_counter == opt->show_n_first_packets)
		exit(0);

	packet_counter++;
	// printf("Total: %d Current: %d\n", opt->show_n_first_packets, packet_counter); //DEBUG

	if(eth->ether_type == htons(0x0800)) { //IP
		struct ip_hdr* ip_header;
		ip_header = build_ip_header(packet);
		if(ip_header->ip_proto == ICMP){ // IP-ICMP
			printf("This is an ICMP Packet.\n");// DEBUG
		} 
		else if(ip_header->ip_proto == UDP){ // IP-UDP
			printf("This is an UDP Packet.\n");// DEBUG
		} 
		else if(ip_header->ip_proto == TCP){ // IP-TCP
			printf("This is a TCP Packet.\n");// DEBUG
		} 
		else {
			printf("This analyzer doesn't know this packet's protocol.\n");
		}
	} else if(eth->ether_type == htons(0x0806)) { // ARP
		printf("This is an ARP Packet.\n");// DEBUG
	} else {
		printf("This analyzer doesn't know this packet's protocol.\n");
	}
}

volatile sig_atomic_t flag = 0;
void flag_setter(){
	flag = 1;
}

unsigned char* get_mac_adress(char *iface){


	int fd;
    struct ifreq ifr;
    // char *iface = "eth0";
    unsigned char *mac;
     
    fd = socket(AF_INET, SOCK_DGRAM, 0);
 
    ifr.ifr_addr.sa_family = AF_INET;
    strncpy(ifr.ifr_name , iface , IFNAMSIZ-1);
 
    ioctl(fd, SIOCGIFHWADDR, &ifr);
 
    close(fd);
     
    mac = (unsigned char *)ifr.ifr_hwaddr.sa_data;

     
    return mac;
    
}

void basic_mode(struct ether_hdr* eth, unsigned char* packet, struct options* opt){
  static struct statistics stat;

  if(flag == 1){
    print_statistics(&stat);
    printf("END OF EXECUTION\n"); //TODO: trocar pela chamada da função que mostra as estatísticas
    // aqui vai a funçao que imprime o struct
    exit(0);
  }

  stat.ethernet_frames += 1;

	int n_of_ffs = 0;
	int i;

	// investigar mais se broadcast realmente é assim
	for(i = 0; i < 6; i++){
		if(eth->ether_dhost[i] == 0xff) n_of_ffs++;
	}

	if(n_of_ffs == 6){ 
		stat.ethernet_broadcast++;
	}else{
		if(memcmp(get_mac_adress(opt->iface), eth->ether_dhost, 6) == 0)
    		stat.to_this_host++;
		 }

    // printf("IFACE: %u\n", get_mac_adress(opt->iface)); // DEBUG
    // print_eth_address("MAC LIDO", get_mac_adress(opt->iface));// DEBUG
    // print_eth_address("MAC RECEBIDO",eth->ether_dhost);// DEBUG



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

struct ip_hdr* build_ip_header(unsigned char* packet){
	struct ip_hdr* ip_header = (struct ip_hdr*) (packet+BYTES_UNTIL_BODY);
	// printf("\nIP ip_v: %hx\n", ip_header->ip_v);//DEBUG
	// print_eth_address("IP src ADRESS", ntohs(ip_header->ip_src)); //DEBUG
	// print_eth_address("IP dest ADRESS", ntohs(ip_header->ip_dst)); //DEBUG
	// printf("\n");
	// for(int i = 0; i < len; i++)	{
	// 	printf("%3X", buffer[i]);

	// }

  // printf("\n");
	return ip_header;
}

/* */
// Break this function to implement the functionalities of your packet analyser
void do_process(unsigned char* packet, int len, struct options* opt) {
  // printf("entrei na do_process\n"); //DEBUG
	if(!len || len < MIN_PACKET_SIZE)
		return;

	struct ether_hdr* eth = (struct ether_hdr*) packet;

	// print_eth_address("\nDst =", eth->ether_dhost);
	// print_eth_address(" Src =", eth->ether_shost);
	// printf(" Ether Type = 0x%04X Size = %d", ntohs(eth->ether_type), len);

  if(opt->mode == BASIC_MODE){
    // printf("Entrou no if basic mode\n"); //DEBUG
		printf("Capturing packets... Ctrl+C to exit. \n");
    	basic_mode(eth, packet, opt);
  } else if(opt->mode == VERBOSE_MODE){
  	verbose_mode(eth, packet, opt);

  } else if(opt->mode == EXTENDED_VERBOSE_MODE){
  	extended_verbose_mode(eth, packet, opt);
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
	set_options(opt, argc, argv);

	// END: dealing with user's parameters in command line

  if(opt->mode == BASIC_MODE){
    struct sigaction act;
    act.sa_handler = &flag_setter;
    // act.sa_flags = 0;
    act.sa_flags = SA_RESTART | SA_NOCLDSTOP;
    sigemptyset (&act.sa_mask);
    // sigaction(SIGINT, &act, NULL);

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
  // printf("antes do while(1) da main\n"); //DEBUG
	while(1) {
		n = recvfrom(sockfd, packet_buffer, MAX_PACKET_SIZE, 0, &saddr, &saddr_len);
    // printf("passou do recv\n");//DEBUG
		if(n < 0) {
			fprintf(stderr, "ERROR: %s\n", strerror(errno));
			exit(1);
		}
		do_process(packet_buffer, n, opt);
	}

	free(packet_buffer);
	close(sockfd);

	return 0;
}
/* */
