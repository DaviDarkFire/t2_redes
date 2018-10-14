#ifndef __STRUCT_DEALER__
  #define __STRUCT_DEALER__

  struct options* init_options();
  struct statistics init_statistics();
  unsigned int set_options(struct options *opt, int argc, char** argv);
  void print_statistics(struct statistics *stat);

#endif
