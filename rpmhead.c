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
#include <errno.h>

#include "rpmhead.h"
#include "util.h"


/****************************************************************
 *
 * rpm header
 *
 */

struct rpmhead *
readhead(int fd, int pad)
{
  unsigned char intro[16];
  int cnt, dcnt, l;
  struct rpmhead *h;

  l = xread(fd, intro, 16);
  if (l == 0)
    return 0;
  if (l != 16)
    {
      fprintf(stderr, "header read error\n");
      return 0;
    }
  if (intro[0] != 0x8e || intro[1] != 0xad || intro[2] != 0xe8 || intro[3] != 0x01)
    {
      fprintf(stderr, "bad header\n");
      return 0;
    }
  cnt  = intro[8] << 24  | intro[9] << 16  | intro[10] << 8 | intro[11];
  dcnt = intro[12] << 24 | intro[13] << 16 | intro[14] << 8 | intro[15];
  if ((dcnt & 7) && pad)
    dcnt += 8 - (dcnt & 7);
  h = xmalloc(sizeof(*h) + cnt * 16 + dcnt);
  memcpy(h->intro, intro, 16);
  if (xread(fd, h->data, cnt * 16 + dcnt) != cnt * 16 + dcnt)
    {
      fprintf(stderr, "header read error\n");
      free(h);
      return 0;
    }
  h->cnt = cnt;
  h->dcnt = dcnt;
  h->dp = h->data + cnt * 16;
  return h;
}

struct rpmhead *
readhead_buf(unsigned char *buf, int len, int pad)
{
  int cnt, dcnt;
  struct rpmhead *h;

  if (len < 16)
    {
      fprintf(stderr, "bad header\n");
      return 0;
    }
  if (buf[0] != 0x8e || buf[1] != 0xad || buf[2] != 0xe8 || buf[3] != 0x01)
    {
      fprintf(stderr, "bad header\n");
      return 0;
    }
  cnt  = buf[8] << 24  | buf[9] << 16  | buf[10] << 8 | buf[11];
  dcnt = buf[12] << 24 | buf[13] << 16 | buf[14] << 8 | buf[15];
  if ((dcnt & 7) && pad)
    dcnt += 8 - (dcnt & 7);
  if (len < 16 + cnt * 16 + dcnt)
    {
      fprintf(stderr, "bad header\n");
      return 0;
    }
  h = xmalloc(sizeof(*h) + cnt * 16 + dcnt);
  memcpy(h->intro, buf, 16);
  memcpy(h->data, buf + 16, cnt * 16 + dcnt);
  h->cnt = cnt;
  h->dcnt = dcnt;
  h->dp = h->data + cnt * 16;
  return h;
}

unsigned int *
headint32(struct rpmhead *h, int tag, int *cnt)
{
  unsigned int i, o, *r;
  unsigned char *d, taga[4];

  d = h->data;
  taga[0] = tag >> 24;
  taga[1] = tag >> 16;
  taga[2] = tag >> 8;
  taga[3] = tag;
  for (i = 0; i < h->cnt; i++, d += 16)
    if (d[3] == taga[3] && d[2] == taga[2] && d[1] == taga[1] && d[0] == taga[0])
      break;
  if (i >= h->cnt)
    return 0;
  if (d[4] != 0 || d[5] != 0 || d[6] != 0 || d[7] != 4)
    return 0;
  o = d[8] << 24 | d[9] << 16 | d[10] << 8 | d[11];
  i = d[12] << 24 | d[13] << 16 | d[14] << 8 | d[15];
  if (o + 4 * i > h->dcnt)
    return 0;
  d = h->dp + o;
  r = xmalloc2(i ? i : 1, sizeof(unsigned int));
  if (cnt)
    *cnt = i;
  for (o = 0; o < i; o++, d += 4)
    r[o] = d[0] << 24 | d[1] << 16 | d[2] << 8 | d[3];
  return r;
}

unsigned int *
headint16(struct rpmhead *h, int tag, int *cnt)
{
  unsigned int i, o, *r;
  unsigned char *d, taga[4];

  d = h->data;
  taga[0] = tag >> 24;
  taga[1] = tag >> 16;
  taga[2] = tag >> 8;
  taga[3] = tag;
  for (i = 0; i < h->cnt; i++, d += 16)
    if (d[3] == taga[3] && d[2] == taga[2] && d[1] == taga[1] && d[0] == taga[0])
      break;
  if (i >= h->cnt)
    return 0;
  if (d[4] != 0 || d[5] != 0 || d[6] != 0 || d[7] != 3)
    return 0;
  o = d[8] << 24 | d[9] << 16 | d[10] << 8 | d[11];
  i = d[12] << 24 | d[13] << 16 | d[14] << 8 | d[15];
  if (o + 2 * i > h->dcnt)
    return 0;
  d = h->dp + o;
  r = xmalloc2(i ? i : 1, sizeof(unsigned int));
  if (cnt)
    *cnt = i;
  for (o = 0; o < i; o++, d += 2)
    r[o] = d[0] << 8 | d[1];
  return r;
}

char *
headstring(struct rpmhead *h, int tag)
{
  unsigned int i, o;
  unsigned char *d, taga[4];
  d = h->data;
  taga[0] = tag >> 24;
  taga[1] = tag >> 16;
  taga[2] = tag >> 8;
  taga[3] = tag;
  for (i = 0; i < h->cnt; i++, d += 16)
    if (d[3] == taga[3] && d[2] == taga[2] && d[1] == taga[1] && d[0] == taga[0])
      break;
  if (i >= h->cnt)
    return 0;
  if (d[4] != 0 || d[5] != 0 || d[6] != 0 || d[7] != 6)
    return 0;
  o = d[8] << 24 | d[9] << 16 | d[10] << 8 | d[11];
  return (char *)h->dp + o;
}

char **
headstringarray(struct rpmhead *h, int tag, int *cnt)
{
  unsigned int i, o;
  unsigned char *d, taga[4];
  char **r;

  d = h->data;
  taga[0] = tag >> 24;
  taga[1] = tag >> 16;
  taga[2] = tag >> 8;
  taga[3] = tag;
  for (i = 0; i < h->cnt; i++, d += 16)
    if (d[3] == taga[3] && d[2] == taga[2] && d[1] == taga[1] && d[0] == taga[0])
      break;
  if (i >= h->cnt)
    return 0;
  if (d[4] != 0 || d[5] != 0 || d[6] != 0 || d[7] != 8)
    return 0;
  o = d[8] << 24 | d[9] << 16 | d[10] << 8 | d[11];
  i = d[12] << 24 | d[13] << 16 | d[14] << 8 | d[15];
  r = xmalloc2(i ? i : 1, sizeof(char *));
  if (cnt)
    *cnt = i;
  d = h->dp + o;
  for (o = 0; o < i; o++)
    {
      r[o] = (char *)d;
      if (o + 1 < i)
	d += strlen((char *)d) + 1;
      if (d >= h->dp + h->dcnt)
	{
	  free(r);
	  return 0;
	}
    }
  return r;
}

unsigned char *
headbin(struct rpmhead *h, int tag, int len)
{
  unsigned int i, o;
  unsigned char *d, taga[4];
  d = h->data;
  taga[0] = tag >> 24;
  taga[1] = tag >> 16;
  taga[2] = tag >> 8;
  taga[3] = tag;
  for (i = 0; i < h->cnt; i++, d += 16)
    if (d[3] == taga[3] && d[2] == taga[2] && d[1] == taga[1] && d[0] == taga[0])
      break;
  if (i >= h->cnt)
    return 0;
  if (d[4] != 0 || d[5] != 0 || d[6] != 0 || d[7] != 7)
    return 0;
  i = d[12] << 24 | d[13] << 16 | d[14] << 8 | d[15];
  if (len != i)
    return 0;
  o = d[8] << 24 | d[9] << 16 | d[10] << 8 | d[11];
  return (unsigned char *)h->dp + o;
}

int
headtagtype(struct rpmhead *h, int tag)
{
  unsigned int i;
  unsigned char *d, taga[4];
  d = h->data;
  taga[0] = tag >> 24;
  taga[1] = tag >> 16;
  taga[2] = tag >> 8;
  taga[3] = tag;
  for (i = 0; i < h->cnt; i++, d += 16)
    if (d[3] == taga[3] && d[2] == taga[2] && d[1] == taga[1] && d[0] == taga[0])
      return d[4] << 24 | d[5] << 16 | d[6] << 8 | d[7];
  return 0;
}

char **
headexpandfilelist(struct rpmhead *h, int *cnt)
{
  char **filenames;
  char **basenames, **dirnames;
  char *cp;
  unsigned int *diridx;
  int i, l;

  filenames = headstringarray(h, TAG_FILENAMES, cnt);
  if (filenames)
    return filenames;
  basenames = headstringarray(h, TAG_BASENAMES, cnt);
  dirnames = headstringarray(h, TAG_DIRNAMES, (int *)0);
  diridx = headint32(h, TAG_DIRINDEXES, (int *)0);
  if (!basenames || !dirnames || !diridx)
    {
      *cnt = 0;
      return 0;
    }
  l = 0;
  for (i = 0; i < *cnt; i++)
    l += strlen(dirnames[diridx[i]]) + strlen(basenames[i]) + 1;
  filenames = xmalloc(*cnt * sizeof(char *) + l);
  cp = (char *)(filenames + *cnt);
  for (i = 0; i < *cnt; i++)
    {
      sprintf(cp, "%s%s", dirnames[diridx[i]], basenames[i]);
      filenames[i] = cp;
      cp += strlen(cp) + 1;
    }
  free(basenames);
  free(dirnames);
  free(diridx);
  return filenames;
}

char *headtonevr(struct rpmhead *h)
{
  char *name;
  unsigned int *epoch; 
  char *version;
  char *release;
  char *nevr;
  int epochcnt = 0;

  name = headstring(h, TAG_NAME);
  version  = headstring(h, TAG_VERSION);
  release  = headstring(h, TAG_RELEASE);
  epoch = headint32(h, TAG_EPOCH, &epochcnt);
  if (!name || !version || !release)
    {
      fprintf(stderr, "headtonevr: bad rpm header\n");
      exit(1);
    }
  if (epoch && epochcnt)
    {
      char epochbuf[11];	/* 32bit decimal will fit in */
      sprintf(epochbuf, "%u", *epoch);
      nevr = xmalloc(strlen(name) + 1 + strlen(epochbuf) + 1 + strlen(version) + 1 + strlen(release) + 1);
      sprintf(nevr, "%s-%s:%s-%s", name, epochbuf, version, release);
    }
  else
    {
      nevr = xmalloc(strlen(name) + 1 + strlen(version) + 1 + strlen(release) + 1);
      sprintf(nevr, "%s-%s-%s", name, version, release);
    }
  if (epoch)
    free(epoch);
  return nevr;
}
