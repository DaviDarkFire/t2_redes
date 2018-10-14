// código baseado em https://www.geeksforgeeks.org/stack-data-structure-introduction-program/

#include "defines.h"
#include <limits.h>

struct stack_node{
    unsigned long int data;
    struct stack_node* next;
};

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
    printf("%lu pushed to stack\n", data); //DEBUG
}

unsigned long int pop(struct stack_node** root){
    if (isEmpty(*root))
        return 0;
    struct stack_node* temp = *root;
    *root = (*root)->next;
    unsigned long int popped = temp->data;
    free(temp);

    printf("%lu popped from stack\n", popped); //DEBUG
    return popped;
}

unsigned long int peek(struct stack_node* root){
    if (isEmpty(root))
        return 0;
    return root->data;
}

// void compute_stack(unsigned char* packet, struct stack_node** root, char** filters, unsigned int len){
//   unsigned int i;
//   struct ether_hdr* eth = (struct ether_hdr*) packet;
//
//   struct ip_hdr* ip;
//   struct tcp_hdr* tcp;
//   struct udp_hdr* udp;
//   struct icmp_hdr* icmp;
//   struct arp_hdr* arp;
//
//   char isIP = 0, isARP = 0, isTCP = 0, isUDP = 0, isICMP = 0;
//
//   if(eth->ether_type == htons(0x0800)){ //IP
//     struct ip_hdr* ip = (struct ip_hdr*) (packet+BYTES_UNTIL_BODY);
//     isIP = 1;
//     switch(ip->proto){
//         case TCP:
//           tcp = (struct tcp_hdr*) (packet+BYTES_UNTIL_BODY+BYTES_UNTIL_IP_DATA);
//           isTCP = 1;
//         break;
//
//         case UDP:
//           udp = (struct udp_hdr*) (packet+BYTES_UNTIL_BODY+BYTES_UNTIL_IP_DATA);
//           isUDP = 1;
//         break;
//
//         case ICMP:
//           icmp = (struct icmp_hdr*) (packet+BYTES_UNTIL_BODY+BYTES_UNTIL_IP_DATA);
//           isICMP = 1;
//         break;
//
//         default:
//         break;
//     }
//   } else {
//     if(eth->ethertype == htons(0x806)){ //ARP
//       arp = (struct arp_hdr*) (packet+BYTES_UNTIL_BODY);
//       isARP = 1;
//     }
//   }
//
//   for(i = 0; i < len; i++){
//     // protocols
//     if(strcmp(filters[i], "tcp")){
//       if(isTCP) push(&root,1);
//     }
//   }
// }
