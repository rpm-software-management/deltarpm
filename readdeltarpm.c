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

/*****************************************************************
 * fileblock handling, maintain everything we want to know about the
 * filelist
 * 
 */

int
headtofb(struct rpmhead *h, struct fileblock *fb)
{
  unsigned int *digestalgoarray;
  fb->h = h;
  fb->filelinktos = fb->filemd5s = 0;
  fb->filemodes = fb->filesizes = 0;
  fb->filenames = headexpandfilelist(h, &fb->cnt);
  if (!fb->filenames)
    {
      fb->cnt = 0;
      return 0;
    }
  fb->filemodes = headint16(h, TAG_FILEMODES, (int *)0);
  fb->filesizes = headint32(h, TAG_FILESIZES, (int *)0);
  fb->filerdevs = headint16(h, TAG_FILERDEVS, (int *)0);
  fb->filelinktos = headstringarray(h, TAG_FILELINKTOS, (int *)0);
  fb->filemd5s = headstringarray(h, TAG_FILEMD5S, (int *)0);
  fb->digestalgo = 1;
  if ((digestalgoarray = headint32(h, TAG_FILEDIGESTALGO, (int *)0)))
    {
      fb->digestalgo = digestalgoarray[0];
      free(digestalgoarray);
    }
  if (fb->digestalgo != 1 && fb->digestalgo != 8)
    {
      fprintf(stderr, "Unknown digest type: %d\n", fb->digestalgo);
      exit(1);
    }
  return 0;
}

/*****************************************************************
 * sequence handling, uncompress the sequence string, check if
 * it matches the installed rpm header, check files if requested.
 */

struct seqdescr *
expandseq(unsigned char *seq, int seql, int *nump, struct fileblock *fb, int (*checkfunc)(char *, int, unsigned char *, unsigned int))
{
  unsigned char *s;
  char *fn;
  int *res;
  int i, n, n2, num, nib, shi, tog, jump, pos;
  unsigned int rdev, lsize;
  MD5_CTX seqmd5;
  unsigned char seqmd5res[16];
  struct seqdescr *sd;
  drpmuint off;
  unsigned char fmd5[32];
  int error = 0;

  n = num = nib = shi = jump = pos = 0;
  tog = 1;

  res = xmalloc2(fb->cnt, sizeof(unsigned int));
  seql -= 16;
  for (i = 0, s = seq + 16; i < seql; )
    {
      if (!nib)
        n2 = (*s >> 4);
      else
	{
          n2 = (*s & 0x0f);
	  s++;
	  i++;
	}
      nib ^= 1;
      if (n2 & 8)
	{
	  n2 ^= 8;
	  if (shi)
	    n2 <<= shi;
	  n |= n2;
	  shi += 3;
	  continue;
	}
      if (shi)
	n2 <<= shi;
      shi = 0;
      n2 |= n;
      n = 0;
      if (jump)
	{
	  jump = 0;
	  pos = n2;
	  tog = 1;
          continue;
	}
      if (n2 == 0)
	{
	  jump = 1;
	  continue;
	}
      if (!tog)
	{
	  pos += n2;
	  tog = 1;
	  continue;
	}
      for (; n2 > 0; n2--)
	{
	  if (num >= fb->cnt || pos >= fb->cnt)
	    {
	      fprintf(stderr, "corrupt delta: bad sequence\n");
	      exit(1);
	    }
	  res[num++] = pos++;
	}
      tog = 0;
    }
  if (shi)
    {
      fprintf(stderr, "corrupt delta: bad sequence\n");
      exit(1);
    }
  res = xrealloc2(res, num, sizeof(unsigned int));
  sd = xmalloc2(num + 1, sizeof(*sd));
  if (nump)
    *nump = num + 1;
  rpmMD5Init(&seqmd5);
  off = 0;
  for (n = 0; n < num; n++)
    {
      i = sd[n].i = res[n];
      lsize = rdev = 0;
      if (S_ISREG(fb->filemodes[i]))
	lsize = fb->filesizes[i];
      else if (S_ISLNK(fb->filemodes[i]))
	lsize = strlen(fb->filelinktos[i]);
      if (S_ISBLK(fb->filemodes[i]) || S_ISCHR(fb->filemodes[i]))
	rdev = fb->filerdevs[i];
      fn = fb->filenames[i];
      if (*fn == '/')
	fn++;
      rpmMD5Update(&seqmd5, (unsigned char *)fn, strlen(fn) + 1);
      rpmMD5Update32(&seqmd5, fb->filemodes[i]);
      rpmMD5Update32(&seqmd5, lsize);
      rpmMD5Update32(&seqmd5, rdev);
      sd[n].cpiolen = 110 + 2 + strlen(fn) + 1;
      if (sd[n].cpiolen & 3)
	sd[n].cpiolen += 4 - (sd[n].cpiolen & 3);
      sd[n].datalen = lsize;
      if (sd[n].datalen & 3)
	sd[n].datalen += 4 - (sd[n].datalen & 3);
      if (S_ISLNK(fb->filemodes[i]))
	rpmMD5Update(&seqmd5, (unsigned char *)fb->filelinktos[i], strlen(fb->filelinktos[i]) + 1);
      else if (S_ISREG(fb->filemodes[i]) && lsize)
	{
	  if (fb->digestalgo == 1)
	    parsemd5(fb->filemd5s[i], fmd5);
	  else
	    parsesha256(fb->filemd5s[i], fmd5);
	  if (checkfunc && checkfunc(fb->filenames[i], fb->digestalgo, fmd5, lsize))
	    error = 1;
	  if (fb->digestalgo == 1)
	    rpmMD5Update(&seqmd5, fmd5, 16);
	  else
	    rpmMD5Update(&seqmd5, fmd5, 32);
	}
      sd[n].off = off;
      off += sd[n].cpiolen + sd[n].datalen;
      sd[n].f = 0;
    }
  sd[n].i = -1;
  sd[n].cpiolen = 124;
  sd[n].datalen = 0;
  sd[n].off = off;
  sd[n].f = 0;
  rpmMD5Final(seqmd5res, &seqmd5);
  free(res);
  if (memcmp(seqmd5res, seq, 16) || error)
    {
      fprintf(stderr, "delta does not match installed data\n");
      exit(1);
    }
  return sd;
}

static unsigned int bzread4(struct cfile *bfp)
{
  unsigned char d[4];
  if (bfp->read(bfp, d, 4) != 4)
    {
      perror("bzread4 error");
      exit(1);
    }
  return d[0] << 24 | d[1] << 16 | d[2] << 8 | d[3]; 
}

void
readdeltarpm(char *n, struct deltarpm *d, struct cfile **cfp)
{
  int dfd;
  struct cfile *bfp;
  unsigned int nevrl;
  drpmuint off;
  int i;

  memset((char *)d, 0, sizeof(*d));
  d->name = n;
  if (!strcmp(n, "-"))
    dfd = 0;
  else if ((dfd = open(n, O_RDONLY)) < 0)
    {
      perror(n);
      exit(1);
    }
  if (xread(dfd, d->rpmlead, 12) != 12)
    {
      fprintf(stderr, "%s: not a delta rpm\n", n);
      exit(1);
    }
  if (d->rpmlead[0] == 'd' && d->rpmlead[1] == 'r' && d->rpmlead[2] == 'p' && d->rpmlead[3] == 'm')
    {
      unsigned char *p;
      d->version = (d->rpmlead[4] << 24) | (d->rpmlead[5] << 16) | (d->rpmlead[6] << 8) | d->rpmlead[7];
      if ((d->version & 0xffffff00) != 0x444c5400)
	{
	  fprintf(stderr, "%s: not a delta rpm\n", n);
	  exit(1);
	}
      if (d->version != 0x444c5431 && d->version != 0x444c5432 && d->version != 0x444c5433)
	{
	  fprintf(stderr, "%s: unsupported version: %c\n", n, (d->version & 255));
	  exit(1);
	}
      nevrl = (d->rpmlead[8] << 24) | (d->rpmlead[9] << 16) | (d->rpmlead[10] << 8) | d->rpmlead[11];
      d->targetnevr = xmalloc(nevrl + 4);	/* also room for 4 bytes addblklen */
      if (xread(dfd, d->targetnevr, nevrl + 4) != nevrl + 4)
	{
	  fprintf(stderr, "%s: read error add data\n", n);
	  exit(1);
	}
      p = (unsigned char *)d->targetnevr + nevrl;
      d->addblklen = (p[0] << 24) | (p[1] << 16) | (p[2] << 8) | p[3];
      d->targetnevr[nevrl] = 0;
      if (d->addblklen)
	{
	  d->addblk = xmalloc(d->addblklen);
	  if (xread(dfd, d->addblk, d->addblklen) != d->addblklen)
	    {
	      fprintf(stderr, "%s: read error add data\n", n);
	      exit(1);
	    }
	}
      d->h = 0;
      if ((bfp = cfile_open(CFILE_OPEN_RD, dfd, 0, CFILE_COMP_XX, CFILE_LEN_UNLIMITED, 0, 0)) == 0)
	{
	  fprintf(stderr, "%s: payload open failed\n", n);
	  exit(1);
	}
    }
  else
    {
      if (d->rpmlead[0] != 0xed || d->rpmlead[1] != 0xab || d->rpmlead[2] != 0xee || d->rpmlead[3] != 0xdb)
	{
	  fprintf(stderr, "%s: not a delta rpm\n", n);
	  exit(1);
	}
      if (xread(dfd, d->rpmlead + 12, 96 - 12) != 96 - 12)
	{
	  fprintf(stderr, "%s: not a delta rpm\n", n);
	  exit(1);
	}
      if (d->rpmlead[4] != 0x03 || d->rpmlead[0x4e] != 0 || d->rpmlead[0x4f] != 5)
	{
	  fprintf(stderr, "%s: not a v3 rpm or not new header styles\n", n);
	  exit(1);
	}
      d->h = readhead(dfd, 1);
      if (!d->h)
	{
	  fprintf(stderr, "%s: could not read signature header\n", n);
	  exit(1);

	}
      free(d->h);
      d->h = readhead(dfd, 0);
      if (!d->h)
	{
	  fprintf(stderr, "%s: could not read header\n", n);
	  exit(1);
	}
      d->targetnevr = headtonevr(d->h);
      if ((bfp = cfile_open(CFILE_OPEN_RD, dfd, 0, CFILE_COMP_XX, CFILE_LEN_UNLIMITED, 0, 0)) == 0)
	{
	  fprintf(stderr, "%s: payload open failed\n", n);
	  exit(1);
	}
      d->addblklen = 0;
    }
  d->deltacomp = bfp->comp;
  d->version = bzread4(bfp);
  if ((d->version & 0xffffff00) != 0x444c5400)
    {
      fprintf(stderr, "%s: not a delta rpm\n", n);
      exit(1);
    }
  if (d->version != 0x444c5431 && d->version != 0x444c5432 && d->version != 0x444c5433)
    {
      fprintf(stderr, "%s: unsupported version: %c\n", n, (d->version & 255));
      exit(1);
    }
  if (!d->h && d->version < 0x444c5433)
    {
      fprintf(stderr, "%s: rpm only deltarpm with old version\n", n);
      exit(1);
    }
  nevrl = bzread4(bfp);
  d->nevr = xmalloc(nevrl + 1);
  d->nevr[nevrl] = 0;
  if (bfp->read(bfp, d->nevr, nevrl) != nevrl)
    {
      fprintf(stderr, "%s: read error nevr\n", n);
      exit(1);
    }
  d->seql = bzread4(bfp);
  if (d->seql < 16)
    {
      fprintf(stderr, "%s: corrupt delta\n", n);
      exit(1);
    }
  d->seq = xmalloc(d->seql);
  if (bfp->read(bfp, d->seq, d->seql) != d->seql)
    {
      fprintf(stderr, "%s: read error seq\n", n);
      exit(1);
    }
  if (bfp->read(bfp, d->targetmd5, 16) != 16)
    {
      fprintf(stderr, "%s: read error md5\n", n);
      exit(1);
    }
  d->targetcomppara = 0;
  d->offadjn = 0;
  d->offadjs = 0;
  if (d->version != 0x444c5431)
    {
      d->targetsize = bzread4(bfp);
      d->targetcomp = bzread4(bfp);
      d->targetcompparalen = bzread4(bfp);
      if (d->targetcompparalen)
	{
	  d->targetcomppara = xmalloc(d->targetcompparalen);
	  if (bfp->read(bfp, d->targetcomppara, d->targetcompparalen) != d->targetcompparalen)
	    {
	      fprintf(stderr, "%s: read error comppara\n", n);
	      exit(1);
	    }
	}
      if (d->version != 0x444c5432)
	{
	  d->compheadlen = bzread4(bfp);
	  d->offadjn = bzread4(bfp);
	  d->offadjs = 0;
	  if (d->offadjn)
	    {
	      d->offadjs = xmalloc2(d->offadjn, 2 * sizeof(unsigned int));
	      for (i = 0; i < d->offadjn; i++)
		d->offadjs[2 * i] = bzread4(bfp);
	      for (i = 0; i < d->offadjn; i++)
		{
		  unsigned int a = bzread4(bfp);
		  if ((a & 0x80000000) != 0)
		    a = (unsigned int)(-(int)(a ^ 0x80000000));
		  d->offadjs[2 * i + 1] = a;
		}
	    }
	}
    }
  else
    {
      char *compressor = headstring(d->h, TAG_PAYLOADCOMPRESSOR);
      if (compressor && !strcmp(compressor, "lzma"))
	d->targetcomp = CFILE_COMP_LZMA;
      else if (compressor && !strcmp(compressor, "bzip2"))
	d->targetcomp = CFILE_COMP_BZ;
      else
	d->targetcomp = CFILE_COMP_GZ;
      d->targetsize = 0;
      d->targetcompparalen = 0;
    }
  d->leadl = bzread4(bfp);
  if (d->leadl < 96 + 16)
    {
      fprintf(stderr, "%s: corrupt delta\n", n);
      exit(1);
    }
  d->lead = xmalloc(d->leadl);
  if (bfp->read(bfp, d->lead, d->leadl) != d->leadl)
    {
      fprintf(stderr, "%s: read error lead\n", n);
      exit(1);
    }
  d->payformatoff = bzread4(bfp);
  if (d->h && d->payformatoff > d->h->dcnt - 4)
    {
      fprintf(stderr, "%s: bad payformat offset\n", n);
      exit(1);
    }
  d->inn = bzread4(bfp);
  d->outn = bzread4(bfp);
  d->in = xmalloc2(d->inn, 2 * sizeof(unsigned int));
  d->out = xmalloc2(d->outn, 2 * sizeof(unsigned int));
  d->paylen = 0;
  for (i = 0; i < d->inn; i++)
    d->in[2 * i] = bzread4(bfp);
  for (i = 0; i < d->inn; i++)
    {
      d->in[2 * i + 1] = bzread4(bfp);
      d->paylen += d->in[2 * i + 1];
    }
  for (i = 0; i < d->outn; i++)
    d->out[2 * i] = bzread4(bfp);
  for (i = 0; i < d->outn; i++)
    {
      d->out[2 * i + 1] = bzread4(bfp);
      d->paylen += d->out[2 * i + 1];
    }

  d->outlen = 0;
  if (d->version > 0x444c5432)
    {
#ifdef DELTARPM_64BIT
      d->outlen = (drpmuint)bzread4(bfp) << 32;
#else
      if (bzread4(bfp) != 0)
	{
	  fprintf(stderr, "%s: deltarpm needs support for archives > 4GB\n", n);
	  exit(1);
	}
#endif
    }
  d->outlen |= bzread4(bfp);
  if (d->addblklen)
    {
      if (bzread4(bfp))
	{
	  fprintf(stderr, "%s: two add data blocks\n", n);
	  exit(1);
	}
    }
  else
    {
      d->addblklen = bzread4(bfp);
      if (d->addblklen)
	{
	  d->addblk = xmalloc(d->addblklen);
	  if (bfp->read(bfp, d->addblk, d->addblklen) != d->addblklen)
	    {
	      fprintf(stderr, "%s: read error add data\n", n);
	      exit(1);
	    }
	}
    }
  d->inlen = 0;
  if (d->version > 0x444c5432)
    {
#ifdef DELTARPM_64BIT
      d->inlen = (drpmuint)bzread4(bfp) << 32;
#else
      if (bzread4(bfp) != 0)
	{
	  fprintf(stderr, "%s: deltarpm needs support for archives > 4GB\n", n);
	  exit(1);
	}
#endif
    }
  d->inlen |= bzread4(bfp);
  if (cfp)
    *cfp = bfp;
  else
    {
      d->indata = xmalloc(d->inlen);
      if (bfp->read(bfp, d->indata, d->inlen) != d->inlen)
	{
	  fprintf(stderr, "%s: read error deltarpm data\n", n);
	  exit(1);
	}
      bfp->close(bfp);
    }
  off = 0;
  for (i = 0; i < d->inn; i++)
    {
      off += d->in[2 * i + 1];
      if (off > d->inlen)
	{
	  fprintf(stderr, "%s: corrupt delta instructions\n", n);
	  exit(1);
	}
    }
  off = 0;
  for (i = 0; i < d->outn; i++)
    {
      if (d->out[2 * i] & 0x80000000)
	d->out[2 * i] = (unsigned int)(-(int)(d->out[2 * i] ^ 0x80000000));
      off += (int)d->out[2 * i];
      if (off > d->outlen) 
	{
	  fprintf(stderr, "corrupt delta instructions (outdata off %llu > %llu)\n", (unsigned long long)off, (unsigned long long)d->outlen);
	  exit(1);
	}
      off += d->out[2 * i + 1];
      if (off < 1 || off > d->outlen)
	{
	  fprintf(stderr, "corrupt delta instructions (outdata off + len %llu > %llu)\n", (unsigned long long)off, (unsigned long long)d->outlen);
	  exit(1);
	}
    }
  d->sdesc = 0;
  d->nsdesc = 0;
  d->outptr = 0;
  d->next = d->prev = 0;
  if (!cfp && strcmp(d->name, "-") != 0)
    close(dfd);
}
