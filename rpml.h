/*
 * Copyright (c) 2004 Michael Schroeder (mls@suse.de)
 *
 * This program is licensed under the BSD license, read LICENSE.BSD
 * for further information
 */

#include <stdio.h>

struct rpmlfile {
  char *name;
  unsigned int mode;
  unsigned int fflags;
  unsigned char md5[16];
};

extern char *rpmlread(FILE *fp, char *fn, int nomagic, struct rpmlfile **filesp, int *nfilesp);

