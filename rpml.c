/*
 * Copyright (c) 2004 Michael Schroeder (mls@suse.de)
 *
 * This program is licensed under the BSD license, read LICENSE.BSD
 * for further information
 */

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <sys/stat.h>

#include "rpml.h"
#include "util.h"
#include "rpmhead.h"

/****************************************************************
 *
 * rpml
 *
 */

static int
rpmlget16(FILE *fp)
{
  int r;
  r = getc(fp);
  r = r << 8 | getc(fp);
  return r;
}

static int
rpmlget32(FILE *fp)
{
  int r;
  r = getc(fp);
  r = r << 8 | getc(fp);
  r = r << 8 | getc(fp);
  r = r << 8 | getc(fp);
  return r;
}

static char *
rpmlgetstr(FILE *fp)
{
  int l;
  char *s, *s2;

  l = getc(fp);
  s = s2 = xmalloc(l + 2);
  while(l-- > 0)
    *s2++ = getc(fp);
  *s2 = 0;
  return s;
}

static void
rpmlskip(FILE *fp, int l)
{
  while(l-- > 0)
    (void)getc(fp);
}

static char *
rpmlgetfn(FILE *fp, char **lastfnp, int *lastfnlp)
{
  int ol, l;
  char *n;
  char *lastfn = *lastfnp;
  int lastfnl = *lastfnlp;

  ol = getc(fp);
  if (ol == EOF)
    {
      fprintf(stderr, "rpmlgetfn: EOF reached!\n");
      exit(1);
    }
  l = getc(fp);
  if (l == 255)
    l = rpmlget16(fp);
  if (l + ol + 1 > lastfnl)
    {
      lastfn = xrealloc(lastfn, l + ol + 1);
      lastfnl = l + ol + 1;
    }
  n = lastfn + ol;
  while(l-- > 0)
    *n++ = getc(fp);
  *n = 0;
  *lastfnp = lastfn;
  *lastfnlp = lastfnl;
  return lastfn;
}

char *
rpmlread(FILE *fp, char *fn, int nomagic, struct rpmlfile **filesp, int *nfilesp)
{
  int lastfnl = 0;
  char *lastfn = 0;
  char *n, *name, *evr, *nevr;
  char *buildhost;
  unsigned int buildtime;
  int patchescnt, filec, i;
  struct rpmlfile *files = 0;
  int nfiles = 0;
  unsigned int mode, s, ogs;

  if (!nomagic && rpmlget32(fp) != 0x52504d4c)
    {
      fprintf(stderr, "%s: not an rpml file\n", fn);
      exit(1);
    }
  name = rpmlgetstr(fp);
  evr = rpmlgetstr(fp);
  nevr = xmalloc(strlen(name) + strlen(evr) + 2);
  sprintf(nevr, "%s-%s", name, evr);
  buildhost = rpmlgetstr(fp);
  buildtime = rpmlget32(fp);
  patchescnt = rpmlget16(fp);
  xfree(name);
  xfree(evr);
  xfree(buildhost);
  if (patchescnt)
    {
      for (i = 0; i < patchescnt; i++)
	rpmlgetstr(fp);
      filec = rpmlget32(fp);
      for (i = 0; i < filec; i++)
	{
	  if ((nfiles & 15) == 0)
	    files = xrealloc(files, (nfiles + 16) * sizeof(*files));
	  n = rpmlgetfn(fp, &lastfn, &lastfnl);
	  files[nfiles].name = xmalloc(strlen(n) + 1);
	  strcpy(files[nfiles].name, n);
	  files[nfiles].mode = S_IFREG;
	  files[nfiles].fflags = FILE_UNPATCHED;
	  memset(files[nfiles].md5, 0, 16);
	  nfiles++;
	}
    }
  for (;;)
    {
      n = rpmlgetfn(fp, &lastfn, &lastfnl);
      if (!*n)
	break;
      if ((nfiles & 15) == 0)
	files = xrealloc(files, (nfiles + 16) * sizeof(*files));
      if (*n == '.' && n[1] == '/')
	n += 2;
      files[nfiles].name = xmalloc(strlen(n) + 1);
      strcpy(files[nfiles].name, n);
      files[nfiles].fflags = 0;
      memset(files[nfiles].md5, 0, 16);
      mode = rpmlget16(fp);
      files[nfiles].mode = mode;
      if (mode == 0)	/* hard link chain */
	{
	   nfiles++;
	   continue;
	}
      ogs = getc(fp);
      if (ogs == 0xff)
	{
	  unsigned int ogs2;
	  ogs2 = getc(fp);
	  ogs = getc(fp);
	  if (ogs2)
	    rpmlskip(fp, ogs2 + 1);
	  if (ogs & 0xfc)
	    rpmlskip(fp, (ogs >> 2 & 0x3f) + 1);
	}
      else
	{
	  if (ogs & 0xe0)
	    rpmlskip(fp, (ogs >> 5 & 7) + 1);
	  if (ogs & 0x1c)
	    rpmlskip(fp, (ogs >> 2 & 7) + 1);
	}
      if (S_ISCHR(mode) || S_ISBLK(mode))
	rpmlget32(fp);	/* rdev */
      if (S_ISREG(mode) || S_ISLNK(mode))
	{
	  ogs &= 3;
	  s = 0;
	  if (ogs > 2)
	    s |= getc(fp) << 24;
	  if (ogs > 1)
	    s |= getc(fp) << 16;
	  if (ogs > 0)
	    s |= getc(fp) << 8;
	  s |= getc(fp);
	  if (s)
	    {
	      for (s = 0; s < 16; s++)
		files[nfiles].md5[s] = getc(fp);
	    }
	}
      nfiles++;
    }
  *filesp = files;
  *nfilesp = nfiles;
  return nevr;
}
