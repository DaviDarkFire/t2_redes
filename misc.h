#ifndef __MISC__
  #define __MISC__

  void print_current_time();
  char * get_address_as_string_from_uint(unsigned int uint_address);
  unsigned char* get_mac_adress(char *iface);
  struct ip_hdr* build_ip_header(unsigned char* packet);
  struct icmp_hdr* build_icmp_header(unsigned char* packet);

#endif
