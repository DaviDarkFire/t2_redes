#include "defines.h"
#include "stack.h"
#include "misc.h"
#include <ctype.h>

void compute_stack(/*unsigned char* packet,*/ struct stack_node** root, char** filters, unsigned int len){
  unsigned int i;
  // struct ether_hdr* eth = (struct ether_hdr*) packet;
  //
  // struct ip_hdr* ip;
  // struct tcp_hdr* tcp;
  // struct udp_hdr* udp;
  // struct icmp_hdr* icmp;
  // struct arp_hdr* arp;

  // char isIP = 0, isARP = 0, isTCP = 0, isUDP = 0, isICMP = 0;

  // if(eth->ether_type == htons(0x0800)){ //IP
  //   struct ip_hdr* ip = (struct ip_hdr*) (packet+BYTES_UNTIL_BODY);
  //   isIP = 1;
  //   switch(ip->proto){
  //       case TCP:
  //         tcp = (struct tcp_hdr*) (packet+BYTES_UNTIL_BODY+BYTES_UNTIL_IP_DATA);
  //         isTCP = 1;
  //       break;
  //
  //       case UDP:
  //         udp = (struct udp_hdr*) (packet+BYTES_UNTIL_BODY+BYTES_UNTIL_IP_DATA);
  //         isUDP = 1;
  //       break;
  //
  //       case ICMP:
  //         icmp = (struct icmp_hdr*) (packet+BYTES_UNTIL_BODY+BYTES_UNTIL_IP_DATA);
  //         isICMP = 1;
  //       break;
  //
  //       default:
  //       break;
  //   }
  // } else {
  //   if(eth->ethertype == htons(0x806)){ //ARP
  //     arp = (struct arp_hdr*) (packet+BYTES_UNTIL_BODY);
  //     isARP = 1;
  //   }
  // }

  for(i = 0; i < len; i++){
    // primitives
    printf("O QUE TEM NO FILTRO:   %s\n", filters[i]); //DEBUG
    if(filters[i][2] == ':'){ // ethernet address
      unsigned long int eth_addr;
      eth_addr = get_ulint_ether_addr_from_string(filters[i]);
      push(root, eth_addr);
    } else if(filters[i][1] == '.' || filters[i][2] == '.' || filters[i][3] == '.'){ // ip address
      unsigned long int ip_addr;
      ip_addr = get_ulint_ip_addr_from_string(filters[i]);
      push(root, ip_addr);
    } else if(filters[i][0] == '0' && filters[i][1] == 'x'){ // hex number
      unsigned long int hex;
      hex = (unsigned long int)strtol(filters[i], NULL, 16);
      push(root, hex);
    } else if(isdigit(filters[i][0])){ // dec number
      push(root, atoi(filters[i]));
    }

    // L&A Operators
    else if(strcmp(filters[i], "eq") == 0){
      unsigned long int a, b, eq;
      b = pop(root);
      a = pop(root);
      eq = (unsigned long int)(a==b);
      printf("passei pelo EQ do parser\n"); //DEBUG
      push(root, eq);
    } else if(strcmp(filters[i], "and") == 0){
      unsigned long int a, b, and;
      b = pop(root);
      a = pop(root);
      and = (unsigned long int)(a && b);
      printf("passei pelo AND do parser\n"); //DEBUG
      push(root, and);
    } else if(strcmp(filters[i], "or") == 0){
      unsigned long int a, b, or;
      b = pop(root);
      a = pop(root);
      or = (unsigned long int)(a || b);
      printf("passei pelo OR do parser\n"); //DEBUG
      push(root, or);
    } else if(strcmp(filters[i], "not") == 0){
      unsigned long int a, not;
      a = pop(root);
      not = (unsigned long int)(!a);
      printf("passei pelo ! do parser\n"); //DEBUG
      push(root, not);
    } else if(strcmp(filters[i], "+") == 0){
      unsigned long int a, b, add;
      b = pop(root);
      a = pop(root);
      add = (a + b);
      printf("passei pelo + do parser\n"); //DEBUG
      push(root, add);
    } else if(strcmp(filters[i], "-") == 0){
      unsigned long int a, b, sub;
      b = pop(root);
      a = pop(root);
      sub = (a - b);
      printf("passei pelo - do parser\n"); //DEBUG
      push(root, sub);
    } else if(strcmp(filters[i], "*") == 0){
      unsigned long int a, b, mult;
      b = pop(root);
      a = pop(root);
      mult = a*b;
      printf("passei pelo * do parser\n"); //DEBUG
      push(root, mult);
    } else if(strcmp(filters[i], "/") == 0){
      unsigned long int a, b, divi;
      b = pop(root);
      a = pop(root);
      divi = (a / b);
      printf("passei pelo / do parser\n"); //DEBUG
      push(root, divi);
    } else if(strcmp(filters[i], "%") == 0){
      unsigned long int a, b, mod;
      b = pop(root);
      a = pop(root);
      mod = (a % b);
      printf("passei pelo %% do parser\n"); //DEBUG
      push(root, mod);
    }

    // OBS: fora do calc, implementaremos os filtros relacionados a protocolo
    else{
      printf("to no ultima elsao\n");// DEBUG
      push(root, 0);
    }


    // Protocols

    // ethernet

    // IP

    // udp

    // tcp

    // icmp
  }
}

int main(int argc, char** argv){
  char** filters = argv+1;
  struct stack_node* root = NULL;
  compute_stack(&root, filters, argc-1);
  if(root == NULL) printf("Erro\n");
  printf("resultado: %lu\n", root->data);
}
