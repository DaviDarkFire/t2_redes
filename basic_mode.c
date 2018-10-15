#include "defines.h"
#include "misc.h"
#include "struct_dealer.h"

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
