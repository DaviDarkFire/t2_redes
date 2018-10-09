#ifndef __MISC__
  #define __MISC__

  void print_current_time();
  char * get_address_as_string_from_uint(unsigned int uint_address);
  unsigned char* get_mac_adress(char *iface);
  struct ip_hdr* build_ip_header(unsigned char* packet);
  struct tcp_hdr* build_tcp_header(unsigned char* packet);
  struct udp_hdr* build_udp_header(unsigned char* packet);
  struct arp_hdr* build_arp_header(unsigned char* packet);
  char* translate_address(char* address);
#endif