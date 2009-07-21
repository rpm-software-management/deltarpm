/*
 * Copyright (c) 2005 Michael Schroeder (mls@suse.de)
 *
 * This program is licensed under the BSD license, read LICENSE.BSD
 * for further information
 */

#define _LARGEFILE64_SOURCE

#include <stdio.h>
#include <string.h>
#include <stdlib.h>

#include "rpmoffs.h"

static unsigned int
get4(unsigned char *p)
{
  return p[0] | p[1] << 8 | p[2] << 16 | p[3] << 24;
}

static unsigned int
get4n(unsigned char *p)
{
  return p[0] << 24 | p[1] << 16 | p[2] << 8 | p[3];
}

static void
readblk(FILE *fp, unsigned char *blk, unsigned int num)
{
  if (fseeko64(fp, 0x800 * (off64_t)num, SEEK_SET) != 0)
    {
      perror("fseeko");
      exit(1);
    }
  if (fread(blk, 0x800, 1, fp) != 1)
    {
      perror("fread");
      exit(1);
    }
}

static struct rpmpay *rpmpays;
static int rpmpayn;

static void
addrpm(char *name, off64_t o, unsigned int l)
{
  char *n;
  if ((rpmpayn & 31) == 0)
    {
      if (rpmpays == 0)
	rpmpays = malloc(32 * sizeof(*rpmpays));
      else
	rpmpays = realloc(rpmpays, (rpmpayn + 32) * sizeof(*rpmpays));
      if (!rpmpays)
	{
	  fprintf(stderr, "out of mem\n");
	  exit(1);
	}
    }
  n = name ? strdup(name) : 0;
  if (name && !n)
    {
      fprintf(stderr, "out of mem\n");
      exit(1);
    }
  rpmpays[rpmpayn].name = n;
  rpmpays[rpmpayn].o = o;
  rpmpays[rpmpayn].l = l;
  rpmpays[rpmpayn].x = 0;
  rpmpays[rpmpayn].lx = 0;
  rpmpayn++;
}

static int
sortrpmcmp(const void *av, const void *bv)
{
  const struct rpmpay *a = av;
  const struct rpmpay *b = bv;
  if (a->o < b->o)
    return -1;
  if (a->o > b->o)
    return 1;
  return strcmp(a->name, b->name);
}

static void
sortrpm()
{
  if (!rpmpayn)
    return;
  qsort(rpmpays, rpmpayn, sizeof(*rpmpays), sortrpmcmp);
}

int
rpmoffs(FILE *fp, char *isoname, struct rpmpay **retp)
{
  unsigned char blk[0x800];
  unsigned char blk2[0x800];
  unsigned char name[256];
  int namel;
  unsigned int filepos, filelen, filepos2, hstart;
  unsigned char *pt, *ep;
  int i, j, l, nl, el, nml, nmf, hcnt, hdcnt;

  unsigned int path_table_size;
  unsigned int path_table_pos;
  unsigned int dirpos, dirlen;
  int sp_bytes_skip = 0;
  unsigned int ce_blk;
  unsigned int ce_off;
  unsigned int ce_len;

  off64_t paystart;
  int paylen;

  readblk(fp, blk, 16);
  if (memcmp(blk, "\001CD001", 6))
    {
      fprintf(stderr, "primary volume descriptor missing\n");
      exit(1);
    }
  path_table_size = get4(blk + 132);
  path_table_pos = get4(blk + 140);
  pt = malloc(path_table_size);
  if (!pt)
    {
      fprintf(stderr, "out of mem\n");
      exit(1);
    }
  readblk(fp, blk, path_table_pos);
  if (fseeko64(fp, 0x800 * (off64_t)path_table_pos, SEEK_SET) != 0)
    {
      perror("fseeko64");
      exit(1);
    }
  if (fread(pt, path_table_size, 1, fp) != 1)
    {
      perror("fread");
      exit(1);
    }
  for (i = 0; i < path_table_size; )
    {
      l = pt[i];
      if (l == 0)
	{
	  fprintf(stderr, "empty dir in path table\n");
	  exit(1);
	}
      dirpos = get4(pt + i + 2);
      i += 8 + l + (l & 1);
      readblk(fp, blk, dirpos);
      dirlen = get4(blk + 10);
      if (dirlen & 0x7ff)
	{
	  fprintf(stderr, "bad directory len\n");
	  exit(1);
	}
      for(j = 0; dirlen; )
	{
	  if (j == 0x800 || (l = blk[j]) == 0)
	    {
	      readblk(fp, blk, ++dirpos);
	      j = 0;
	      dirlen -= 0x800;
	      continue;
	    }
	  if (j + l > 0x800)
	    {
	      fprintf(stderr, "bad dir entry\n");
	      exit(1);
	    }
	  if ((blk[j + 25] & 2) != 0)	/* directory? */
	    {
	      j += l;
	      continue;
	    }
	  if ((blk[j + 25] & 4) != 0)	/* associated file? */
	    {
	      fprintf(stderr, "associated file\n");
	      exit(1);
	    }
	  if (blk[j + 26] != 0 || blk[j + 27] != 0)
	    {
	      fprintf(stderr, "interleaved file\n");
	      exit(1);
	    }
	  filepos = get4(blk + j + 2);
	  filelen = get4(blk + j + 10);
	  nl = blk[j + 32];
	  if (nl == 0 || j + nl + 33 > 0x800)
	    {
	      fprintf(stderr, "bad dir entry\n");
	      exit(1);
	    }
	  if ((nl & 1) == 0)
	    nl++;
	  ep = blk + j + 33 + nl;
	  el = l - nl - 33;
	  if (el >= 7 && ep[0] == 'S' && ep[1] == 'P')
	    sp_bytes_skip = ep[6];
	  else
	    {
	      ep += sp_bytes_skip;
	      el -= sp_bytes_skip;
	    }
	  ce_len = 0;
	  ce_blk = 0;
	  ce_off = 0;
	  namel = 0;
	  nmf = 0;
	  for (;;)
	    {
	      if (el <= 2)
		{
		  if (!ce_len)
		    break;
		  readblk(fp, blk2, ce_blk);
		  ep = blk2 + ce_off;
		  el = ce_len;
		  ce_len = 0;
		}
	      if (ep[0] == 'C' && ep[1] == 'E')
		{
		  ce_blk = get4(ep + 4);
		  ce_off = get4(ep + 12);
		  ce_len = get4(ep + 20);
		}
	      else if (ep[0] == 'N' && ep[1] == 'M')
		{
		  nml = ep[2] - 5;
		  if ((nmf & 1) == 0)
		    namel = 0;
		  nmf = ep[4];
		  if (namel + nml + 2 >= sizeof(name))
		    {
		      fprintf(stderr, "name overflow\n");
		      exit(1);
		    }
		  strncpy((char *)name + namel, (char *)ep + 5, nml);
		  namel += nml;
		  name[namel] = 0;
		}
	      el -= ep[2];
	      ep += ep[2];
	    }
	  j += l;
	  if (namel < 5)
	    continue;
	  if (filelen < 0x70 || strcmp((char *)name + namel - 4, ".rpm"))
	    continue;
	  readblk(fp, blk2, filepos);
	  filepos2 = filepos;
	  if (get4(blk2) != 0xdbeeabed)
	    continue;
	  if (get4(blk2 + 0x60) != 0x01e8ad8e)
	    {
	      fprintf(stderr, "bad rpm (bad sigheader): %s\n", name);
	      exit(1);
	    }
	  hcnt = get4n(blk2 + 0x68);
	  hdcnt = get4n(blk2 + 0x6c);
	  if ((hdcnt & 7) != 0)
	   hdcnt += 8 - (hdcnt & 7);
          if (0x70 + hcnt * 16 + hdcnt + 0x70 >= filelen)
	    {
	      fprintf(stderr, "bad rpm (no header): %s\n", name);
	      exit(1);
	    }
	  hstart = 0x70 + hcnt * 16 + hdcnt;
          if (hstart >= 0x800)
	    {
	      filepos2 += hstart / 0x800;
	      readblk(fp, blk2, filepos2);
	      hstart &= 0x7ff;
	    }
	  if (get4(blk2 + hstart) != 0x01e8ad8e)
	    {
	      fprintf(stderr, "bad rpm (bad header): %s\n", name);
	      exit(1);
	    }
	  hstart += 8;
          if (hstart >= 0x800)
	    {
	      filepos2++;
	      readblk(fp, blk2, filepos2);
	      hstart &= 0x7ff;
	    }
	  hcnt = get4n(blk2 + hstart);
	  hdcnt = get4n(blk2 + hstart + 4);
	  hstart += 0x8 + hcnt * 16 + hdcnt;
          if (hstart >= 0x800)
	    {
	      filepos2 += hstart / 0x800;
	      hstart &= 0x7ff;
            }
	  if (hstart + (filepos2 - filepos) * 0x800 > filelen)
	    {
	      fprintf(stderr, "bad rpm (no payload): %s\n", name);
	      exit(1);
	    }
	  paystart = 0x800 * (off64_t)filepos2 + hstart;
	  paylen = filelen - (hstart + (filepos2 - filepos) * 0x800);
	  namel -= 4;
          name[namel] = 0;
	  l = namel;
	  if (l > 6 && !strncmp((char *)name + l - 6, ".patch", 6))
	    l -= 6;
	  if (l > 6 && !strncmp((char *)name + l - 6, ".delta", 6))
	    l -= 6;
	  l--;
	  while (l > 0 && name[l] != '.')
	    l--;
	  if (l)
	    {
	      int l2 = l;
	      l--;
	      while (l > 0 && name[l] != '-')
		l--;
	      if (l)
		{
		  l--;
		  while (l > 0 && name[l] != '-')
		    l--;
		  if (l)
		    {
		      memmove(name + l, name + l2, namel - l2 + 1);
		      namel -= l2 - l;
		    }
		}
	    }
	  addrpm((char *)name, paystart, paylen);
	}
    }
  sortrpm();
  addrpm(0, 0, 0);
  i = rpmpayn - 1;
  *retp = rpmpays;
  rpmpayn = 0;
  rpmpays = 0;
  return i;
}
