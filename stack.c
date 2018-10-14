// código baseado em https://www.geeksforgeeks.org/stack-data-structure-introduction-program/

#include "defines.h"
#include <limits.h>

struct stack_node{
    unsigned int data;
    struct stack_node* next;
};

struct stack_node* new_node(unsigned int data){
    struct stack_node* node =
              (struct stack_node*) malloc(sizeof(struct stack_node));
    node->data = data;
    node->next = NULL;
    return node;
}

int isEmpty(struct stack_node *root){
    return !root;
}

void push(struct stack_node** root, unsigned int data){
    struct stack_node* node = new_node(data);
    node->next = *root;
    *root = node;
    printf("%d pushed to stack\n", data); //DEBUG
}

int pop(struct stack_node** root){
    if (isEmpty(*root))
        return INT_MIN;
    struct stack_node* temp = *root;
    *root = (*root)->next;
    int popped = temp->data;
    free(temp);

    return popped;
}

int peek(struct stack_node* root){
    if (isEmpty(root))
        return INT_MIN;
    return root->data;
}

void compute_stack(unsigned char* packet, struct stack_node** root, char** filters, unsigned int len){
  unsigned int i;
  struct ether_hdr* eth = (struct ether_hdr*) packet;
  if(eth->ether_type == htons(0x0800)){ //IP
    struct ip_hdr* ip = (struct ip_hdr*) (packet+BYTES_UNTIL_BODY);
    // ...
  }

  for(i = 0; i < len; i++){
    if(strcmp(filters[i], "tcp")){
      
    }
  }
}
