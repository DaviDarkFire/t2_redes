#include "defines.h"

void init_options(struct options* opt){
  opt->mode = BASIC_MODE;
  opt->show_n_first_packets = DONT_USE_OPTION;
  opt->shouldnt_translate_names = DONT_USE_OPTION;
}

struct statistics init_statistics(){
  struct statistics stat;
  stat.ethernet_frames = 0;
	stat.ethernet_broadcast = 0;
	stat.arp = 0;
	stat.ip = 0;
	stat.icmp = 0;
	stat.udp = 0;
	stat.tcp = 0;
	stat.to_this_host = 0;
  return stat;
}

unsigned int set_options(struct options *opt, int argc, char** argv){
  int i;
  unsigned int count_opt = 0;
  for(i = 0; i < argc; i++){
    if(strcmp(argv[i], "-i") == 0){
        opt->iface = argv[i+1];
        count_opt++;
        count_opt++;
    }
    if(strcmp(argv[i], "-v") == 0){
        opt->mode = VERBOSE_MODE;
        count_opt++;
    }
    if(strcmp(argv[i], "-V") == 0){
        opt->mode = EXTENDED_VERBOSE_MODE;
        count_opt++;
    }
    if(strcmp(argv[i], "-c") == 0){
        opt->show_n_first_packets = atoi(argv[i+1]);
        count_opt++;
        count_opt++;
    }
    if(strcmp(argv[i], "-n") == 0){
        opt->shouldnt_translate_names = 1;
        count_opt++;
    }
  }
  return count_opt;
}

void print_statistics(struct statistics *stat){
  printf("\nethernet_frames: %u\nethernet_broadcast: %u\nARP: %u\nIP: %u\nICMP: %u\nUDP: %u\nTCP: %u\nTo this host: %u\n",
   stat->ethernet_frames, stat->ethernet_broadcast, stat->arp, stat->ip, stat->icmp, stat->udp, stat->tcp, stat->to_this_host);
}
