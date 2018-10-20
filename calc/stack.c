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
