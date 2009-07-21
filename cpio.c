/*
 * Copyright (c) 2004 Michael Schroeder (mls@suse.de)
 *
 * This program is licensed under the BSD license, read LICENSE.BSD
 * for further information
 */

#include <stdio.h>
#include <stdlib.h>

#include "cpio.h"

/****************************************************************
 *
 * cpio archive
 *
 */

unsigned int cpion(char *s)
{
  int i;  
  unsigned int r = 0;
  for (i = 0; i < 8; i++, s++)
    if (*s >= '0' && *s <= '9') 
      r = (r << 4) | (*s - '0'); 
    else if (*s >= 'a' && *s <= 'f') 
      r = (r << 4) | (*s - ('a' - 10)); 
    else if (*s >= 'A' && *s <= 'F') 
      r = (r << 4) | (*s - ('a' - 10)); 
    else    
      {
        fprintf(stderr, "bad cpio archive\n");
        exit(1);
      }
  return r;
}

