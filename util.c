/*
 * Copyright (c) 2004,2005 Michael Schroeder (mls@suse.de)
 *
 * This program is licensed under the BSD license, read LICENSE.BSD
 * for further information
 */

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <errno.h>

#include "util.h"

/****************************************************************
 *
 * utility functions
 *
 */

void *
xmalloc(size_t len)
{
  void *r = malloc(len ? len : 1);
  if (r)
    return r;
  fprintf(stderr, "Out of memory allocating %zu bytes!\n", len);
  exit(1);
}

void *
xmalloc2(size_t num, size_t len)
{
  if (len && (num * len) / len != num)
    {
      fprintf(stderr, "Out of memory allocating %zu*%zu bytes!\n", num, len);
      exit(1);
    }
  return xmalloc(num * len);
}

void *
xrealloc(void *old, size_t len)
{
  if (old == 0)
    old = malloc(len ? len : 1);
  else
    old = realloc(old, len ? len : 1);
  if (old)
    return old;
  fprintf(stderr, "Out of memory reallocating %zu bytes!\n", len);
  exit(1);
}

void *
xrealloc2(void *old, size_t num, size_t len)
{
  if (len && (num * len) / len != num)
    {
      fprintf(stderr, "Out of memory allocating %zu*%zu bytes!\n", num, len);
      exit(1);
    }
  return xrealloc(old, num * len);
}

void *
xcalloc(size_t num, size_t len)
{
  void *r = calloc(num, len);
  if (r)
    return r;
  fprintf(stderr, "Out of memory allocating %zu*%zu bytes!\n", num, len);
  exit(1);
}

void *
xfree(void *mem)
{
  if (mem)
    free(mem);
  return 0;
}

ssize_t
xread(int fd, void *buf, size_t l)
{
  size_t ol = l;
  ssize_t r;

  while (l)
    {
      r = read(fd, buf, l); 
      if (r < 0) 
	{
	  if (errno == EINTR)
	    continue;
          return r;
	}
      if (r == 0)
        return ol - l;
      buf += r;
      l -= r;
    }
  return ol;
}

int
parsehex(char *s, unsigned char *hex, int len)
{
  int i, r = 0;

  len *= 2;
  for (i = 0; ; i++, s++)
    {
      if (*s == 0 && !(i & 1))
	return i / 2;
      if (i == len)
	{
	  fprintf(stderr, "parsehex: string too long\n");
	  exit(1);
	}
      if (*s >= '0' && *s <= '9')
	r = (r << 4) | (*s - '0');
      else if (*s >= 'a' && *s <= 'f')
	r = (r << 4) | (*s - ('a' - 10));
      else if (*s >= 'A' && *s <= 'F')
	r = (r << 4) | (*s - ('a' - 10));
      else
	{
	  fprintf(stderr, "parsehex: bad string\n");
	  exit(1);
	}
      if ((i & 1) != 0)
	{
	  hex[i / 2] = r;
	  r = 0;
	}
    }
}

void
parsemd5(char *s, unsigned char *md5)
{
  if (!*s)
    {
      memset(md5, 0, 16);
      return;
    }
  if (parsehex(s, md5, 16) != 16)
    {
      fprintf(stderr, "parsemd5: bad md5\n");
      exit(1);
    }
}

void
parsesha256(char *s, unsigned char *sha256)
{
  if (!*s)
    {
      memset(sha256, 0, 32);
      return;
    }
  if (parsehex(s, sha256, 32) != 32)
    {
      fprintf(stderr, "parsesha256: bad sha256\n");
      exit(1);
    }
}

