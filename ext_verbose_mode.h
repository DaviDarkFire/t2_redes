#ifndef __EXT_VERBOSE_MODE__
  #define __EXT_VERBOSE_MODE__

  void extended_verbose_mode(struct ether_hdr* eth, unsigned char* packet, struct options* opt);
  void print_ether_protocol(struct ether_hdr* eth, int packet_counter, int packet_size);
  void print_ip_protocol(struct ip_hdr* ip);
  void print_ip_tos(unsigned char tos);
  void print_ip_flags(unsigned short flags);
  void print_udp_protocol(struct udp_hdr* udp, unsigned char* packet);
  void print_64_data_bytes(unsigned char* protocol, unsigned char* data_start);
  void print_tcp_protocol(struct tcp_hdr* tcp_header,unsigned char* packet);
  void print_tcp_flags(struct tcp_hdr* tcp_header);
#endif
