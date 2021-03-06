// código baseado em https://www.geeksforgeeks.org/stack-data-structure-introduction-program/

#include "defines.h"
#include "stack.h"
#include "misc.h"

struct stack_node* new_node(unsigned long int data){
    struct stack_node* node =
              (struct stack_node*) malloc(sizeof(struct stack_node));
    node->data = data;
    node->next = NULL;
    return node;
}

int isEmpty(struct stack_node *root){
    return !root;
}

void push(struct stack_node** root, unsigned long int data){
    struct stack_node* node = new_node(data);
    node->next = *root;
    *root = node;
}

unsigned long int pop(struct stack_node** root){
    if (isEmpty(*root))
        return 0;
    struct stack_node* temp = *root;
    *root = (*root)->next;
    unsigned long int popped = temp->data;
    free(temp);

    return popped;
}

unsigned long int peek(struct stack_node* root){
    if (isEmpty(root))
        return 0;
    return root->data;
}

void compute_stack(unsigned char* packet, struct stack_node** root, char** filters, unsigned int len){
  unsigned int i;
  struct ether_hdr* eth = (struct ether_hdr*) packet;

  struct ip_hdr* ip = build_ip_header(packet);
  struct tcp_hdr* tcp = build_tcp_header(packet);
  struct udp_hdr* udp = build_udp_header(packet);
  struct icmp_hdr* icmp = build_icmp_header(packet);
  struct arp_hdr* arp = build_arp_header(packet);

  char isIP = 0, isARP = 0, isTCP = 0, isUDP = 0, isICMP = 0;

  if(eth->ether_type == htons(0x0800)){ //IP
    struct ip_hdr* ip = (struct ip_hdr*) (packet+BYTES_UNTIL_BODY);
    isIP = 1;
    switch(ip->ip_proto){
        case TCP:
          isTCP = 1;
        break;

        case UDP:
          isUDP = 1;
        break;

        case ICMP:
          isICMP = 1;
        break;

        default:
        break;
    }
  } else {
    if(eth->ether_type == htons(0x806)){ //ARP
      isARP = 1;
    }
  }

  for(i = 0; i < len; i++){
    // primitives
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
      push(root, eq);
    } else if(strcmp(filters[i], "and") == 0){
      unsigned long int a, b, and;
      b = pop(root);
      a = pop(root);
      and = (unsigned long int)(a && b);
      push(root, and);
    } else if(strcmp(filters[i], "or") == 0){
      unsigned long int a, b, or;
      b = pop(root);
      a = pop(root);
      or = (unsigned long int)(a || b);
      push(root, or);
    } else if(strcmp(filters[i], "not") == 0){
      unsigned long int a, not;
      a = pop(root);
      not = (unsigned long int)(!a);
      push(root, not);
    } else if(strcmp(filters[i], "+") == 0){
      unsigned long int a, b, add;
      b = pop(root);
      a = pop(root);
      add = (a + b);
      push(root, add);
    } else if(strcmp(filters[i], "-") == 0){
      unsigned long int a, b, sub;
      b = pop(root);
      a = pop(root);
      sub = (a - b);
      push(root, sub);
    } else if(strcmp(filters[i], "*") == 0){
      unsigned long int a, b, mult;
      b = pop(root);
      a = pop(root);
      mult = a*b;
      push(root, mult);
    } else if(strcmp(filters[i], "/") == 0){
      unsigned long int a, b, divi;
      b = pop(root);
      a = pop(root);
      divi = (a / b);
      push(root, divi);
    } else if(strcmp(filters[i], "%") == 0){
      unsigned long int a, b, mod;
      b = pop(root);
      a = pop(root);
      mod = (a % b);
      push(root, mod);
    }

    // Protocols
    else if(strcmp(filters[i], "ip") == 0){
        push(root, isIP);
    } else if(strcmp(filters[i], "udp") == 0){
        push(root, isUDP);
    } else if(strcmp(filters[i], "tcp") == 0){
        push(root, isTCP);
    } else if(strcmp(filters[i], "icmp") == 0){
        push(root, isICMP);
    } else if(strcmp(filters[i], "arp") == 0){
        push(root, isARP);
    }

    // ethernet

    else if (strcmp(filters[i], "etherto") == 0){
        unsigned long int ulint_dhost = get_ulint_ether_addr_from_bytes(eth->ether_dhost);
        push(root, ulint_dhost);

    }else if (strcmp(filters[i], "etherfrom") == 0){
        unsigned long int ulint_shost = get_ulint_ether_addr_from_bytes(eth->ether_shost);
        push(root, (unsigned long int)eth->ether_shost);

    }else if (strcmp(filters[i], "ethertype") == 0){
        push(root, (unsigned long int)ntohs(eth->ether_type));

    }

    // IP

    else if (strcmp(filters[i], "ipto") == 0){
        if (isIP)
            push(root, (unsigned long int)ntohl(ip->ip_dst));
        else
            push(root,0);

    }else if (strcmp(filters[i], "ipfrom") == 0){
        if (isIP){
            push(root, (unsigned long int) ntohl(ip->ip_src));
        }else{
            push(root,0);
        }
    }else if (strcmp(filters[i], "ipproto") == 0){
        if (isIP)
            push(root, (unsigned long int)ip->ip_proto);
        else
            push (root, 0);

    }

    // udp

    else if (strcmp(filters[i], "udptoport") == 0){
        if (isUDP)
            push(root, (unsigned long int)ntohs(udp->dst_port));
        else
            push(root,0);

    }else if (strcmp(filters[i], "udpfromport") == 0){
        if (isUDP)
            push(root, (unsigned long int)ntohs(udp->src_port));
        else
            push(root,0);
    }

    // tcp

    else if (strcmp(filters[i], "tcptoport") == 0){
        if (isTCP)
            push(root, (unsigned long int)ntohs(tcp->dst_port));
        else
            push(root,0);

    }else if (strcmp(filters[i], "tcpfromport") == 0){
        if (isTCP)
            push(root, (unsigned long int)ntohs(tcp->src_port));
        else
            push(root,0);
    }

    // icmp

    else if (strcmp(filters[i], "icmptype") == 0){
        if (isICMP)
            push(root, (unsigned long int)icmp->type);
        else
            push(root,0);

    }
  }
}
