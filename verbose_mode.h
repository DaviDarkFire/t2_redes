#ifndef __VERBOSE_MODE__
  #define __VERBOSE_MODE__

  void print_tcp_packet_verbose(struct ip_hdr* ip_header, int translate);
  void verbose_mode(struct ether_hdr* eth, unsigned char* packet, struct options* opt);
  
#endif
