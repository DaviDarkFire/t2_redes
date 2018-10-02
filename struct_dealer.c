#define __STRUCT_DEALER__

#ifndef __DEFINES__
  #include "defines.c"
#endif

struct options init_options(){
  struct options opt;
  opt.mode = BASIC_MODE;
  opt.show_n_first_packets = DONT_USE_OPTION;
  opt.shouldnt_translate_names = DONT_USE_OPTION;
  return opt;
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

void set_options(struct options *opt, int argc, char** argv){
  for(int i = 0; i < argc; i++){
    if(strcmp(argv[i], "-v") == 0) opt->mode = VERBOSE_MODE;
    if(strcmp(argv[i], "-V") == 0) opt->mode = EXTENDED_VERBOSE_MODE;
    if(strcmp(argv[i], "-c") == 0) opt->show_n_first_packets = atoi(argv[i+1]);
    if(strcmp(argv[i], "-n") == 0) opt->shoudlnt_translate_names = 1;
  }
}
