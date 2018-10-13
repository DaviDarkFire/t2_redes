#ifndef __STACK__
 #define __STACK__
 struct stack_node* new_node(unsigned int data);
 int isEmpty(struct stack_node *root);
 void push(struct stack_node** root, unsigned int data);
 int pop(struct stack_node** root);
 int peek(struct stack_node* root);
#endif
