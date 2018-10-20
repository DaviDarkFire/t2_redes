#include "defines.h"
#include "stack.h"
#include "misc.h"
#include <ctype.h>

void compute_stack(/*unsigned char* packet,*/ struct stack_node** root, char** filters, unsigned int len){
  unsigned int i;

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

    // OBS: fora do calc, implementaremos os filtros relacionados a protocolo
    else{
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
