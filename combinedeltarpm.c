/*
 * Copyright (c) 2005 Michael Schroeder (mls@suse.de)
 *
 * This program is licensed under the BSD license, read LICENSE.BSD
 * for further information
 */

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <unistd.h>
#include <string.h>
#include <fcntl.h>

#include <bzlib.h>
#include <zlib.h>
#include <lzma.h>
#include <sys/stat.h>

#include "util.h"
#include "md5.h"
#include "rpmhead.h"
#include "cfile.h"
#include "deltarpm.h"


void
createcpiohead(struct seqdescr *sd, struct fileblock *fb, unsigned char *cpiodata)
{
  int i = sd->i;
  unsigned int lsize, rdev;
  char *np;

  if (i == -1)
    {
      sprintf((char *)cpiodata, "%s%c%c%c%c", "07070100000000000000000000000000000000000000010000000000000000000000000000000000000000000000000000000b00000000TRAILER!!!", 0, 0, 0, 0);
      return;
    }
  lsize = rdev = 0;
  np = fb->filenames[i];
  if (*np == '/')
    np++;
  if (S_ISREG(fb->filemodes[i]))
    lsize = fb->filesizes[i];
  else if (S_ISLNK(fb->filemodes[i]))
    lsize = strlen(fb->filelinktos[i]);
  if (S_ISBLK(fb->filemodes[i]) || S_ISCHR(fb->filemodes[i]))
    rdev = fb->filerdevs[i];
  sprintf((char *)cpiodata, "07070100000000%08x00000000000000000000000100000000%08x0000000000000000%08x%08x%08x00000000./%s%c%c%c%c", fb->filemodes[i], lsize, devmajor(rdev), devminor(rdev), (int)strlen(np) + 3, np, 0, 0, 0, 0);
}



unsigned int *newout;
unsigned int *newin;
unsigned int newoutn;
unsigned int newinn;
unsigned int lastoff;
struct cfile *cfa;
struct cfile *cfd;

void
addin(unsigned char *d, unsigned int l, struct deltarpm *dd)
{
  unsigned char buf[4096];
  int i, l2;
  struct deltarpm *ddd;

  if (newinn && newin[2 * newinn] == 0 && newin[2 * newinn + 1] == 0 && (drpmuint)newin[2 * newinn - 2 + 1] + l < 0x80000000)
    {
      /* add to old */
/*      printf("addin combine %d\n", l); */
      newin[2 * newinn - 2 + 1] += l;
    }
  else
    {
/*      printf("addin %d\n", l); */
      newin[2 * newinn + 1] = l;
      newinn++;
      if (newinn % 16 == 0)
	newin = xrealloc2(newin, newinn + 16 + 1, 2 * sizeof(unsigned int));
      newin[2 * newinn] = 0;
      newin[2 * newinn + 1] = 0;
    }
  if (!dd || !dd->combaddblk)
    {
      if (cfd->write(cfd, d, l) != l)
	{
	  fprintf(stderr, "data block write error\n");
	  exit(1);
	}
      return;
    }
  while (l > 0)
    {
      l2 = l > sizeof(buf) ? sizeof(buf) : l;
      for (i = 0; i < l2; i++)
        buf[i] = *d++;
      for (ddd = dd; ddd; ddd = ddd->prev)
        if (ddd->outptr)
          for (i = 0; i < l2; i++)
	    buf[i] += *ddd->outptr++;
      if (cfd->write(cfd, buf, l2) != l2)
	{
	  fprintf(stderr, "data block write error\n");
	  exit(1);
	}
      l -= l2;
    }
}

void
addout(unsigned int off, unsigned int l, struct deltarpm *dd)
{
  unsigned char buf[4096];
  int i, l2;
  struct deltarpm *ddd;

  if (newin[2 * newinn] && newoutn && lastoff == off && (drpmuint)newout[2 * newoutn - 1] + l < 0x80000000)
    {
/*      printf("addout combine %d\n", l); */
      newout[2 * newoutn - 1] += l;
      lastoff += l;
    }
  else
    {
/*      printf("addout %d\n", l); */
      newin[2 * newinn]++;
      newout[2 * newoutn] = (unsigned int)(off - lastoff);
      newout[2 * newoutn + 1] = l;
      lastoff = off + l;
      newoutn++;
      if (newoutn % 16 == 0)
	newout = xrealloc2(newout, newoutn + 16, 2 * sizeof(unsigned int));
    }
  if (!cfa)
    return;
  while (l > 0)
    {
      l2 = l > sizeof(buf) ? sizeof(buf) : l;
      memset(buf, 0, l2);
      for (ddd = dd; ddd; ddd = ddd->prev)
        if (ddd->outptr)
          for (i = 0; i < l2; i++)
	    buf[i] += *ddd->outptr++;
      if (cfa->write(cfa, buf, l2) != l2)
	{
	  fprintf(stderr, "add block write error\n");
	  exit(1);
	}
      l -= l2;
    }
}


void combine(unsigned int toff, unsigned int tlen, struct deltarpm *d);

void
add_normalized(unsigned int off, unsigned int len, struct deltarpm *d)
{
  struct seqdescr *sd;
  unsigned int *offadj;

  while(len)
    {
/* copy len bytes from position off with add */
/* 1) find header */
      for (sd = d->sdesc; ; sd++)
	if (off < sd->off)
	  {
	    sd--;
	    break;
	  }
	else if (sd->i == -1)
	  break;
/* 2) addin cpio header stuff */
      if (off < sd->off + sd->cpiolen)
	{
	  unsigned int o = off - sd->off;
	  unsigned int l2 = len > sd->cpiolen - o ? sd->cpiolen - o : len;
	  createcpiohead(sd, &d->fb, d->cpiodata);
	  addin(d->cpiodata + o, l2, d);
	  off += l2;
	  len -= l2;
	}
      if (!len)
	break;
/* 2) addin/addout file stuff */
      if (sd->i == -1)
	{
	  /* cpio end reached, addin zeros */
	  unsigned int l2 = len > 16 ? 16 : len;
	  addin((unsigned char *)"\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0", l2, d);
	  off += l2;
	  len -= l2;
	}
      else if (S_ISLNK(d->fb.filemodes[sd->i]))
	{
	  unsigned int o = off - (sd->off + sd->cpiolen);
	  char *ln = d->fb.filelinktos[sd->i];
	  unsigned int l2 = (unsigned int)strlen(ln);
	  if (l2 < o)
	    l2 = 0;
          else
	    l2 -= o;
	  if (l2 > len)
	    l2 = len;
	  if (l2)
	    addin((unsigned char *)ln + o, l2, d);
	  off += l2;
	  len -= l2;
	  o += l2;
	  l2 = len > sd->datalen - o ? sd->datalen - o : len;
	  if (l2 > 0)
	    {
	      addin((unsigned char *)"\0\0\0\0", l2, d);
	      off += l2;
	      len -= l2;
	    }
	}
      else
	{
	  unsigned int o = off - (sd->off + sd->cpiolen);
	  unsigned int l2 = len > sd->datalen - o ? sd->datalen - o : len;
	  unsigned int moff, roff;

	  /* calculate real offset */
	  if (d->offadjs)
	    {
	      for (roff = moff = 0, offadj = d->offadjs; ; offadj += 2)
		{
		  if (moff + offadj[0] > off)
		    {
		      roff += off - moff;
		      break;
		    }
		  moff += offadj[0];
		  roff += offadj[0] + (int)offadj[1];
		}
	      if (off + l2 > moff + offadj[0])
		{
		  fprintf(stderr, "internal error\n");
		  exit(1);
		}
	    }
	  else
	    roff = off;
	  combine(roff, l2, d->next);
	  off += l2;
	  len -= l2;
	}
    }
}

/*
 * create block at roff size rlen with statements from d1
 */

void
combine(unsigned int toff, unsigned int tlen, struct deltarpm *d)
{
  unsigned int ind;
  unsigned int *in, *out;
  unsigned int on, inn;
  unsigned int off, len, l, pos;

  inn = d->inn;
  pos = 0;
  ind = 0;
  in = d->in;
  out = d->out;
  d->outptr = d->addblk ? d->addblk : 0;
  off = 0;
  while (inn > 0 && tlen)
    {
      on = *in++;
      while (on > 0)
	{
	  off += (int)*out++;
	  len = *out++;
	  on--;
	  if (pos + len <=  toff)
	    {
	      pos += len;
	      off += len;
	      if (d->outptr)
		d->outptr += len;
	      continue;
	    }
	  l = toff - pos;
	  pos += l;
	  if (d->outptr)
	    d->outptr += l;
	  off += l;
	  len -= l;
	  l = len > tlen ? tlen : len;
	  if (l)
	    {
	      if (d->next)
		{
		  if (d->sdesc)
		    add_normalized(off, l, d);
		  else
		    combine(off, l, d->next);
		}
	      else
		addout(off, l, d);
	      pos += l;
	      off += l;
	      tlen -= l;
	      toff += l;
	    }
	}
      if (tlen == 0)
	break;
      len = *in++;
      inn--;
      if (pos + len <= toff)
	{
	  ind += len;
	  pos += len;
	  continue;
	}
      l = toff - pos;
      pos += l;
      ind += l;
      len -= l;
      l = len > tlen ? tlen : len;
      if (l)
        addin(d->indata + ind, l, d->prev);
      tlen -= l;
      toff += l;
      ind += l;
      pos += l;
    }
  if (tlen)
    {
      fprintf(stderr, "%s: out of data\n", d->name);
      exit(1);
    }
}

void
expandaddblk(struct deltarpm *d)
{
  struct cfile *cf;
  unsigned int l;
  int i;
  unsigned char *b;

  if (d->addblklen == 0)
    return;
  l = 0;
  for (i = 0; i < d->outn; i++)
    l += d->out[2 * i + 1];
  b = xmalloc(l);
  if ((cf = cfile_open(CFILE_OPEN_RD, CFILE_IO_BUFFER, d->addblk, CFILE_COMP_XX, d->addblklen, 0, 0)) == 0)
    {
      fprintf(stderr, "%s: expandaddblk open error\n", d->name);
      exit(1);
    }
  if (cf->read(cf, b, l) != l)
    {
      fprintf(stderr, "%s: expandaddblk read error\n", d->name);
      exit(1);
    }
  cf->close(cf);
  free(d->addblk);
  d->addblk = b;
  d->addblklen = l;
}

int
str2comp(char *comp)
{
  if (!strcmp(comp, "bzip2"))
    return CFILE_COMP_BZ;
  if (!strcmp(comp, "gzip"))
    return CFILE_COMP_GZ;
#ifdef CFILE_COMP_GZ_RSYNC
  if (!strcmp(comp, "gzip rsyncable"))
    return CFILE_COMP_GZ_RSYNC;
#endif
  if (!strcmp(comp, "lzma"))
    return CFILE_COMP_LZMA;
  if (!strcmp(comp, "uncompressed"))
    return CFILE_COMP_UN;
  fprintf(stderr, "unknown compression type: %s\n", comp);
  exit(1);
}

int
replacelead(struct deltarpm *d, char *rpmname)
{
  unsigned char lead[96];
  int fd;
  struct rpmhead *h, *oldh;
  unsigned char *hmd5, *oldhmd5;
  MD5_CTX targetmd5;
  unsigned char buf[4096];
  unsigned int *hsize;
  int l, size;

  if (strcmp(rpmname, "-") == 0)
    fd = 0;
  else if ((fd = open(rpmname, O_RDONLY)) < 0)
    {
      perror(rpmname);
      exit(1);
    }
  if (read(fd, lead, 96) != 96)
    {
      fprintf(stderr, "%s: not a rpm\n", rpmname);
      exit(1);
    }
  if (lead[0] != 0xed || lead[1] != 0xab || lead[2] != 0xee || lead[3] != 0xdb)
    {
      fprintf(stderr, "%s: not a rpm\n", rpmname);
      exit(1);
    }
  if (lead[4] != 0x03 || lead[0x4e] != 0 || lead[0x4f] != 5)
    {
      fprintf(stderr, "%s: not a v3 rpm or not new header styles\n", rpmname);
      exit(1);
    }
  h = readhead(fd, 1);
  if (!h)
    {
      fprintf(stderr, "%s: could not read signature header\n", rpmname);
      exit(1);
    }
  hmd5 = headbin(h, 1004, 16);
  hsize = headint32(h, 1000, (int *)0);
  oldh = readhead_buf(d->lead + 96, d->leadl - 96, 0);
  if (hmd5 && oldh && (oldhmd5 = headbin(oldh, 1004, 16)) != 0 && memcmp(hmd5, oldhmd5, 16) != 0)
    {
      fprintf(stderr, "%s: rpm does not match deltarpm\n", rpmname);
      exit(1);
    }
  free(oldh);
  if (d->leadl == 96 + 16 + 16 * h->cnt + h->dcnt && !memcmp(d->lead, lead, 96) && !memcmp(d->lead + 96, h->intro, 16) && !memcmp(d->lead + 96 + 16, h->data, d->leadl - 96 - 16))
    {
      /* nothing to do */
      if (strcmp(rpmname, "-") != 0)
        close(fd);
      return 0;
    }
  xfree(d->lead);
  d->leadl = 96 + 16 + 16 * h->cnt + h->dcnt;
  d->lead = xmalloc(d->leadl);
  memcpy(d->lead, lead, 96);
  memcpy(d->lead + 96, h->intro, 16);
  memcpy(d->lead + 96 + 16, h->data, d->leadl - 96 - 16);
  rpmMD5Init(&targetmd5);
  rpmMD5Update(&targetmd5, d->lead, d->leadl);
  size = 0;
  while ((l = read(fd, buf, sizeof(buf))) > 0)
    {
      rpmMD5Update(&targetmd5, buf, l);
      size += l;
    }
  rpmMD5Final(d->targetmd5, &targetmd5);
  if (hsize && size != *hsize)
    {
      fprintf(stderr, "%s: truncated rpm\n", rpmname);
      exit(1);
    }
  free(h);
  if (strcmp(rpmname, "-") != 0)
    close(fd);
  return 1;
}

void
reduce(struct deltarpm *d, int addblkcomp, int isexpanded)
{
  struct deltarpm *dprev, *d2;
  unsigned char *cfabuf;
  unsigned char *cfdbuf;
  unsigned int cfalen;
  unsigned int cfdlen;
  int combaddblk = 0;
  int i;
  unsigned int len;
  
  dprev = d->prev;
  d->prev = 0;

  for (d2 = d; d2; d2 = d2->next)
    {
      if (d2->addblklen)
	combaddblk = 1;
      d2->combaddblk = combaddblk;
      if (d2->next || !isexpanded)
        expandaddblk(d2);
    }
  cfabuf = 0;
  cfa = cfd = 0;
  if (combaddblk)
    cfa = cfile_open(CFILE_OPEN_WR, CFILE_IO_ALLOC, &cfabuf, addblkcomp, CFILE_LEN_UNLIMITED, 0, 0);
  cfd = cfile_open(CFILE_OPEN_WR, CFILE_IO_ALLOC, &cfdbuf, CFILE_COMP_UN, CFILE_LEN_UNLIMITED, 0, 0);
  newin = xmalloc((16 + 1) * 2 * sizeof(unsigned int));
  newout = xmalloc((16) * 2 * sizeof(unsigned int));
  newinn = 0;
  newoutn = 0;
  newin[0] = newin[1] = 0;
  lastoff = 0;

  len = 0;
  for (i = 0; i < d->inn; i++)
    len += d->in[2 * i + 1];
  for (i = 0; i < d->outn; i++)
    len += d->out[2 * i + 1];
  combine(0, len, d);
  cfalen = cfa ? cfa->close(cfa) : 0;
  cfdlen = cfd->close(cfd);
  if (newin[2 * newinn] != 0 || newin[2 * newinn + 1] != 0)
    newinn++;
  for (d2 = d; d2->next; d2 = d2->next)
    ;
  d->nevr = d2->nevr;
  d2->nevr = 0;
  d->seq = d2->seq;
  d2->seq = 0;
  d->seql = d2->seql;
  d->inn = newinn;
  d->outn = newoutn;
  d->in = newin;
  d->out = newout;
  newin = newout = 0;
  newinn = newoutn = 0;
  d->outlen = d2->outlen;
  d->addblklen = cfalen;
  xfree(d->addblk);
  d->addblk = cfabuf;
  d->inlen = cfdlen;
  d->indata = cfdbuf;
  d->offadjs = d2->offadjs;
  d2->offadjs = 0;
  d->offadjn = d2->offadjn;
  d->prev = dprev;
  d->combaddblk = 0;
  d2 = d->next;
  d->next = 0;
  while(d2)
    {
      d = d2;
      d2 = d->next;
      xfree(d->h);
      xfree(d->nevr);
      xfree(d->seq);
      xfree(d->targetnevr);
      xfree(d->targetcomppara);
      xfree(d->lead);
      xfree(d->in);
      xfree(d->out);
      xfree(d->addblk);
      xfree(d->indata);
      xfree(d->offadjs);
      xfree(d->sdesc);
      xfree(d->cpiodata);
      xfree(d);
    }
}

int
main(int argc, char **argv)
{
  int i, j, c;
  unsigned int len;
  char *name;
  struct deltarpm *d, *d2;
  char *compopt = 0;
  char *leadopt = 0;
  int paycomp = CFILE_COMP_XX;
  int addblkcomp = CFILE_COMP_XX;
  int lastaddblkcomp;
  int verbose = 0;
  FILE *vfp;
  int version = 0;
  int isexpanded = 0;
  unsigned int sizemb = 0;
  
  while ((c = getopt(argc, argv, "xvS:z:V:")) != -1)
    {
      switch(c)
	{
	case 'z':
	  compopt = optarg;
	  break;
	case 'S':
	  leadopt = optarg;
	  break;
        case 'v':
	  verbose++;
	  break;
        case 'V':
	  version = atoi(optarg);
	  if (version < 1 || version > 3)
	    {
	      fprintf(stderr, "illegal version: %d\n", version);
	      exit(1);
	    }
	  break;
	default:
	  fprintf(stderr, "usage: combinedeltarpm [-v] [-S rpm] deltarpms... newdeltarpm\n");
	  exit(1);
	}
    }
  if (compopt)
    {
      char *c2 = strchr(compopt, ',');
      if (c2)
	*c2++ = 0;
      if (*compopt && strcmp(compopt, "last") != 0)
	paycomp = str2comp(compopt);
      if (c2)
	addblkcomp = str2comp(c2);
    }

  if (argc - optind < 2)
    {
      fprintf(stderr, "usage: combinedeltarpm [-v] [-S rpm] deltarpms... newdeltarpm\n");
      exit(1);
    }

  vfp = !strcmp(argv[argc - 1], "-") ? stderr : stdout;
  d = 0;
  for (j = optind; j < argc - 1; j++)
    {
      d2 = xmalloc(sizeof(*d2));
      if (verbose)
        fprintf(vfp, "reading %s\n", argv[j]);
      readdeltarpm(argv[j], d2, 0);
      if (d2->version < 0x444c5433)
	{
	  fprintf(stderr, "%s: version lacks support for deltarpm combining\n", d2->name);
	  exit(1);
	}
      if (!d2->h && d2->targetcomp == CFILE_COMP_UN && d2->inn == 0 && d2->outn == 0)
	{
	  struct rpmhead *sighead;
	  unsigned char *hmd5;
	  /* no diff deltarpm, just update lead and targetmd5 */
	  if (!d)
	    {
	      fprintf(stderr, "no diff deltarpm must not be first\n");
	      exit(1);
	    }
	  sighead = readhead_buf(d->lead + 96, d->leadl - 96, 0);
	  if (d2->seql != 16 || !sighead || (hmd5 = headbin(sighead, 1004, 16)) == 0 || memcmp(hmd5, d2->seq, 16) != 0)
	    {
	      fprintf(stderr, "deltarpm %s does not apply to %s\n", d2->name, d->name);
	      exit(1);
	    }
	  xfree(sighead);
	  memcpy(d->targetmd5, d2->targetmd5, 16);
	  xfree(d->lead);
	  d->lead = d2->lead;
	  d->leadl = d2->leadl;
	  xfree(d2);
	  d2 = d;
	  continue;
	}
      sizemb += (unsigned int)(d2->paylen >> 20);
      if (d && d->next && sizemb > 100)
	{
	  if (verbose)
	    fprintf(vfp, "combining deltas (%u MB)\n", sizemb);
	  reduce(d, CFILE_COMP_UN, isexpanded);
	  isexpanded = 1;
          sizemb = (unsigned int)(d->paylen >> 20);
          sizemb += (unsigned int)(d2->paylen >> 20);
	}
      d2->next = d;
      if (d)
	{
	  if ((d->h && !d2->h) || (!d->h && d2->h))
	    {
	      /* standard -> rpm only does not work because the result would
               * be standard and we cannot reconstruct the new header */
	      /* rpm only -> standard does not work because we don't have
               * the header to compensate normalization */
	      fprintf(stderr, "cannot combine deltarpm of different types\n");
	      exit(1);
	    }
	  d->prev = d2;
	  if (d->h && d2->h)
	    {
	      headtofb(d->h, &d2->fb);
	      d2->sdesc = expandseq(d2->seq, d2->seql, &d2->nsdesc, &d2->fb, 0);
	      len = 0;  
	      for (i = 0; d2->sdesc[i].i != -1; i++)
		if (d2->sdesc[i].cpiolen > len)
		  len = d2->sdesc[i].cpiolen;
	      if (len < 124)
		len = 124;                    /* room for tailer */
	      d2->cpiodata = xmalloc(len + 4);    /* extra room for padding */
	      /* extend offadjs entry to end of archive */
	      if (d2->offadjs)
		{
		  drpmuint off = d2->sdesc[i].off;
		  for (i = 0; i < d2->offadjn; i++)
		    {
		      if (off < d2->offadjs[2 * i])
			{
			  fprintf(stderr, "bad offadjs\n");
			  exit(1);
			}
		      off -= d2->offadjs[2 * i];
		    }
		  i = (off / 0x7fffffff) + 1;
		  d2->offadjs = xrealloc2(d2->offadjs, d2->offadjn + i, 2 * sizeof(unsigned int));
		  for (i = 2 * d2->offadjn; ; i += 2)
		    {
		      d2->offadjs[i + 1] = 0;
		      if (off >= 0x80000000)
			{
			  d2->offadjs[i] = 0x7fffffff;
			  continue;
			}
		      d2->offadjs[i] = off;
		      break;
		    }
		}
	    }
	  else
	    {
	      struct rpmhead *sighead;
	      unsigned char *hmd5;
	      sighead = readhead_buf(d->lead + 96, d->leadl - 96, 0);
	      if (d2->seql != 16 || !sighead || (hmd5 = headbin(sighead, 1004, 16)) == 0 || memcmp(hmd5, d2->seq, 16) != 0)
		{
		  fprintf(stderr, "deltarpm %s does not apply to %s\n", d2->name, d->name);
		  exit(1);
		}
	      xfree(sighead);
	      d2->sdesc = 0;
	      d2->nsdesc = 0;
	      d2->offadjs = 0;
	    }
	}
      d = d2;
    }
  name = argv[argc - 1];

  lastaddblkcomp = CFILE_COMP_BZ;
  if (d->addblklen > 9 && d->addblk[0] == 0x1f && d->addblk[1] == 0x8b)
    lastaddblkcomp = CFILE_COMP_GZ;
  if (addblkcomp == CFILE_COMP_XX)
    addblkcomp = lastaddblkcomp;
  if (paycomp == CFILE_COMP_XX)
    paycomp = d->deltacomp;
  if (leadopt)
    replacelead(d, leadopt);

  if (d->next)
    {
      if (verbose)
	fprintf(vfp, "combining deltas\n");
      reduce(d, addblkcomp, isexpanded);
      lastaddblkcomp = addblkcomp;
    }
  if (addblkcomp != lastaddblkcomp && d->addblk)
    {
      unsigned char *newaddblk = 0;
      int newlen;
      newlen = cfile_copy(cfile_open(CFILE_OPEN_RD, CFILE_IO_BUFFER, d->addblk, CFILE_COMP_XX, d->addblklen, 0, 0), cfile_open(CFILE_OPEN_WR, CFILE_IO_ALLOC, &newaddblk, addblkcomp, CFILE_LEN_UNLIMITED, 0, 0), CFILE_COPY_CLOSE_IN|CFILE_COPY_CLOSE_OUT);
      if (newlen < 0)
	{
	  fprintf(stderr, "could not re-compress add data\n");
	  exit(1);
	}
      d->addblklen = (unsigned int)newlen;
      xfree(d->addblk);
      d->addblk = newaddblk;
    }
  d->version = version ? 0x444c5430 + version : d->version;
  d->name = name;
  d->deltacomp = paycomp;
  if (verbose)
    fprintf(vfp, "writing %s\n", name);
  writedeltarpm(d, 0);
  exit(0);
}
