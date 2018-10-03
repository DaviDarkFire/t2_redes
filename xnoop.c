#include "defines.h"
#include "struct_dealer.h"
// #include <signal.h>

volatile sig_atomic_t flag = 0;
void flag_setter(){
	flag = 1;
}

void basic_mode(){
  static struct statistics stat;

  if(flag == 1){
    printf("ethernet_frames: %u\nethernet_broadcast: %u\narp: %u\nip: %u\nicmp: %u\nudp: %u\ntcp: %u\nto_this_host: %u\n", stat.ethernet_frames, stat.ethernet_broadcast, stat.arp, stat.ip, stat.icmp, stat.udp, stat.tcp, stat.to_this_host);
    printf("END OF EXECUTION\n"); //TODO: trocar pela chamada da função que mostra as estatísticas
    // aqui vai a funçao que imprime o struct
    exit(0);
  }


  stat.ethernet_frames += 1;

  //aqui vem os ifs pra saber que tipo de protocolo vai ser, e contabilizar no struct stat


	printf("Capturing packets... Ctrl+C to exit. \n");
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

void build_ip_header(unsigned char* buffer, int len){
	struct ip_hdr* ip_header = (struct ip_hdr*) (buffer+BYTES_UNTIL_BODY);
	printf("\nIP ip_v: %hx\n", ip_header->ip_v);//DEBUG
	// print_eth_address("IP src ADRESS", ntohs(ip_header->ip_src)); //DEBUG
	// print_eth_address("IP dest ADRESS", ntohs(ip_header->ip_dst)); //DEBUG
	// printf("\n");
	// for(int i = 0; i < len; i++)	{
	// 	printf("%3X", buffer[i]);

	// }

     printf("\n");

}

/* */
// Break this function to implement the functionalities of your packet analyser
void do_process(unsigned char* packet, int len, struct options opt) {
  printf("entrei na do_process\n"); //DEBUG
	if(!len || len < MIN_PACKET_SIZE)
		return;

	struct ether_hdr* eth = (struct ether_hdr*) packet;

	print_eth_address("\nDst =", eth->ether_dhost);
	print_eth_address(" Src =", eth->ether_shost);
	printf(" Ether Type = 0x%04X Size = %d", ntohs(eth->ether_type), len);

	build_ip_header(packet, len);


  if(opt.mode == BASIC_MODE){
    printf("Entrou no if basic mode\n"); //DEBUG



    basic_mode();
  } else if(opt.mode == VERBOSE_MODE){

  } else if(opt.mode == EXTENDED_VERBOSE_MODE){

  }
  // vai ficar em outra função que checa tipo
	// if(eth->ether_type == htons(0x0800)) {
	// 	//IP
  //
	// 	//...
	// } else if(eth->ether_type == htons(0x0806)) {
	// 	//ARP
  //
	// 	//...
	// }
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

	struct options opt;
  opt = init_options();
	set_options(&opt, argc, argv);

	// END: dealing with user's parameters in command line

  if(opt.mode == BASIC_MODE){
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
  printf("antes do while(1) da main\n"); //DEBUG
	while(1) {
		n = recvfrom(sockfd, packet_buffer, MAX_PACKET_SIZE, 0, &saddr, &saddr_len);
    printf("passou do recv\n");//DEBUG
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
