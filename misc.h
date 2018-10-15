#ifndef __MISC__
  #define __MISC__

  void print_current_time();
  char * get_address_as_string_from_uint(unsigned int uint_address);
  unsigned char* get_mac_adress(char *iface);
  struct ip_hdr* build_ip_header(unsigned char* packet);
  struct tcp_hdr* build_tcp_header(unsigned char* packet);
  struct udp_hdr* build_udp_header(unsigned char* packet);
  struct arp_hdr* build_arp_header(unsigned char* packet);
  struct icmp_hdr* build_icmp_header(unsigned char* packet);
  char* translate_address(char* address);
  int get_packet_size(unsigned char* packet);
  void printBits(size_t const size, void const * const ptr);
  unsigned long int get_ulint_ether_addr_from_string(char* str_addr);
  unsigned long int get_ulint_ip_addr_from_string(char* str_addr);
  char* get_icmp_type_string(unsigned char type);
  void print_eth_address(char *s, unsigned char *eth_addr);
#endif
