#ifndef __VERBOSE_MODE__
  #define __VERBOSE_MODE__

  void print_ip_packet_verbose(unsigned char* packet, struct ip_hdr* ip_header, int shouldnt_translate);
  void verbose_mode(struct ether_hdr* eth, unsigned char* packet, struct options* opt);
  void print_arp_packet_verbose(unsigned char* packet, int shouldnt_translate);

#endif
