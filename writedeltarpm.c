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

#include "md5.h"
#include "rpmhead.h"
#include "cfile.h"
#include "deltarpm.h"
#include "util.h"

static void
write32(struct cfile *cf, unsigned int d)
{
  unsigned char dd[4];
  dd[0] = d >> 24;
  dd[1] = d >> 16;
  dd[2] = d >> 8;
  dd[3] = d;
  if (cf->write(cf, dd, 4) != 4)
    {
      perror("write32");
      exit(1);
    }
}

void
writedeltarpm(struct deltarpm *d, unsigned char **indatalist)
{
  int fd, i;
  MD5_CTX paymd5;
  unsigned char paymd5res[16];
  unsigned char oldpayformat[4];
  unsigned int written;
  struct cfile *bfd;
  unsigned char sighdr[16 + 16 * 3 + 4 + 16 + 16 + 4];

  if (!d->h && d->version < 0x444c5433)
    {
      fprintf(stderr, "%s: rpm only deltarpm not supported in V1 or V2 deltarpms\n", d->name);
      exit(1);
    }
#ifdef DELTARPM_64BIT
  if ((d->outlen >= 0x100000000ULL || d->inlen >= 0x100000000ULL) && d->version < 0x444c5433)
    {
      fprintf(stderr, "%s: cpio sizes >4GB not supported in V1 or V2 deltarpms\n", d->name);
      exit(1);
    }
#endif
  if (!strcmp(d->name, "-"))
    fd = 1;
  else if ((fd = open(d->name, O_RDWR|O_CREAT|O_TRUNC, 0666)) == -1)
    {
      perror(d->name);
      exit(1);
    }
  rpmMD5Init(&paymd5);
  if (d->h)
    {
      if (write(fd, d->rpmlead, 96) != 96)
	{
	  perror("rpmlead write");
	  exit(1);
	}
      memset(sighdr, 0, sizeof(sighdr));
      sighdr[0] = 0x8e;
      sighdr[1] = 0xad;
      sighdr[2] = 0xe8;
      sighdr[3] = 0x01;
      sighdr[11] = 3;
      sighdr[15] = 4 + 16 + 16;

      sighdr[16*1+3] = 0x3e;        /* HEADER_SIGNATURES */
      sighdr[16*1+7]  = 7;
      sighdr[16*1+11]  = 4 + 16;
      sighdr[16*1+15]  = 16;

      sighdr[16*2+2] = 0x03;        /* size */
      sighdr[16*2+3] = 0xe8;
      sighdr[16*2+7]  = 4;
      sighdr[16*2+15] = 1;

      sighdr[16*3+2] = 0x03;        /* md5 */
      sighdr[16*3+3] = 0xec;
      sighdr[16*3+7]  = 7;
      sighdr[16*3+11] = 4;
      sighdr[16*3+15] = 16;

      sighdr[16 + 16 * 3 + 4 + 16 + 3] = 0x3e;
      sighdr[16 + 16 * 3 + 4 + 16 + 7] = 7;
      sighdr[16 + 16 * 3 + 4 + 16 + 8] = 0xff;
      sighdr[16 + 16 * 3 + 4 + 16 + 9] = 0xff;
      sighdr[16 + 16 * 3 + 4 + 16 + 10] = 0xff;
      sighdr[16 + 16 * 3 + 4 + 16 + 11] = 256 - 3 * 16;
      sighdr[16 + 16 * 3 + 4 + 16 + 15] = 16;

      if (write(fd, sighdr, sizeof(sighdr)) != sizeof(sighdr))
	{
	  perror("sig hdr write");
	  exit(1);
	}
      if (write(fd, d->h->intro, 16) != 16)
	{
	  perror("hdr write");
	  exit(1);
	}
      rpmMD5Update(&paymd5, d->h->intro, 16);
      if (d->payformatoff)
	{
	  memcpy(oldpayformat, d->h->dp + d->payformatoff, 4);
	  memcpy(d->h->dp + d->payformatoff, "drpm", 4);
	}
      if (write(fd, d->h->data, 16 * d->h->cnt + d->h->dcnt) != 16 * d->h->cnt + d->h->dcnt)
	{
	  perror("hdr write");
	  exit(1);
	}
      rpmMD5Update(&paymd5, d->h->data, 16 * d->h->cnt + d->h->dcnt);
      if (d->payformatoff)
	memcpy(d->h->dp + d->payformatoff, oldpayformat, 4);
    }
  else
    {
      unsigned char *intro;
      int nevrlen;
      nevrlen = strlen(d->targetnevr) + 1;
      intro = xmalloc(4 + 4 + 4 + nevrlen + 4);
      memcpy(intro, "drpm", 4);
      intro[4] = d->version >> 24;
      intro[5] = d->version >> 16;
      intro[6] = d->version >> 8;
      intro[7] = d->version;
      intro[8] = nevrlen >> 24;
      intro[9] = nevrlen >> 16;
      intro[10] = nevrlen >> 8;
      intro[11] = nevrlen;
      memcpy(intro + 12 , d->targetnevr, nevrlen);
      intro[12 + nevrlen] = d->addblklen >> 24;
      intro[13 + nevrlen] = d->addblklen >> 16;
      intro[14 + nevrlen] = d->addblklen >> 8;
      intro[15 + nevrlen] = d->addblklen;
      if (write(fd, intro, 4 + 4 + 4 + nevrlen + 4) != 4 + 4 + 4 + nevrlen + 4)
	{
	  perror("header write");
	  exit(1);
	}
      xfree(intro);
      if (d->addblklen)
	{
	  if (write(fd, d->addblk, d->addblklen) != d->addblklen)
	    {
	      perror("add data write");
	      exit(1);
	    }
	}
    }
  if ((bfd = cfile_open(CFILE_OPEN_WR, fd, 0, d->deltacomp, CFILE_LEN_UNLIMITED, (cfile_ctxup)rpmMD5Update, &paymd5)) == 0)
    {
      fprintf(stderr, "payload open failed\n");
      exit(1);
    }
  write32(bfd, d->version);
  write32(bfd, strlen(d->nevr) + 1);
  if (bfd->write(bfd, d->nevr, strlen(d->nevr) + 1) != strlen(d->nevr) + 1)
    {
      fprintf(stderr, "payload write failed\n");
      exit(1);
    }
  write32(bfd, d->seql);
  if (bfd->write(bfd, d->seq, d->seql) != d->seql)
    {
      fprintf(stderr, "payload write failed\n");
      exit(1);
    }
  if (bfd->write(bfd, d->targetmd5, 16) != 16)
    {
      fprintf(stderr, "payload write failed\n");
      exit(1);
    }
  if (d->version != 0x444c5431)
    {
      write32(bfd, d->targetsize);
      write32(bfd, d->targetcomp);
      write32(bfd, 0);
      if (d->version != 0x444c5432)
	{
	  write32(bfd, d->compheadlen);
	  write32(bfd, d->offadjn);
	  for (i = 0; i < d->offadjn; i++)
	    write32(bfd, d->offadjs[2 * i]);
	  for (i = 0; i < d->offadjn; i++)
	    {
	      if ((int)d->offadjs[2 * i + 1] < 0)
	        write32(bfd, (unsigned int)(-(int)d->offadjs[2 * i + 1]) | 0x80000000);
	      else
	        write32(bfd, d->offadjs[2 * i + 1]);
	    }
	}
    }
  write32(bfd, d->leadl);
  if (bfd->write(bfd, d->lead, d->leadl) != d->leadl)
    {
      fprintf(stderr, "payload write failed\n");
      exit(1);
    }
  write32(bfd, d->payformatoff);
  write32(bfd, d->inn);
  write32(bfd, d->outn);
  for (i = 0; i < d->inn; i++)
    write32(bfd, d->in[2 * i]);
  for (i = 0; i < d->inn; i++)
    write32(bfd, d->in[2 * i + 1]);
  for (i = 0; i < d->outn; i++)
    {
      if ((int)d->out[2 * i] < 0)
	write32(bfd, (unsigned int)(-d->out[2 * i]) | 0x80000000);
      else
	write32(bfd, d->out[2 * i]);
    }
  for (i = 0; i < d->outn; i++)
    write32(bfd, d->out[2 * i + 1]);
#ifdef DELTARPM_64BIT
  if (d->version > 0x444c5432)
    write32(bfd, (unsigned int)(d->outlen >> 32));
#else
  if (d->version > 0x444c5432)
    write32(bfd, 0);
#endif
  write32(bfd, (unsigned int)d->outlen);
  if (d->h)
    {
      write32(bfd, d->addblklen);
      if (d->addblklen)
	{
	  if (bfd->write(bfd, d->addblk, d->addblklen) != d->addblklen)
	    {
	      fprintf(stderr, "add data write failed\n");
	      exit(1);
	    }
	}
    }
  else
    write32(bfd, 0);
#ifdef DELTARPM_64BIT
  if (d->version > 0x444c5432)
    write32(bfd, (unsigned int)(d->inlen >> 32));
#else
  if (d->version > 0x444c5432)
    write32(bfd, 0);
#endif
  write32(bfd, (unsigned int)d->inlen);
  if (d->inlen)
    {
      if (indatalist)
	{
	  for (i = 0; i < d->inn; i++)
	    if (bfd->write(bfd, indatalist[i], d->in[2 * i + 1]) != d->in[2 * i + 1])
	      {
	        fprintf(stderr, "data write failed\n");
	        exit(1);
	      }
	}
      else if (bfd->write(bfd, d->indata, d->inlen) != d->inlen)
	{
	  fprintf(stderr, "data write failed\n");
	  exit(1);
	}
    }

  if ((written = bfd->close(bfd)) == -1)
    {
      fprintf(stderr, "payload write failed\n");
      exit(1);
    }
  rpmMD5Final(paymd5res, &paymd5);
  if (d->h)
    {
      if (lseek(fd, (off_t)96, SEEK_SET) == (off_t)-1)
	{
	  fprintf(stderr, "sig seek failed\n");
	  exit(1);
	}
      /* add header size */
      written += 16 + d->h->cnt * 16 + d->h->dcnt;
      sighdr[16 + 16 * 3 + 0] = written >> 24;
      sighdr[16 + 16 * 3 + 1] = written >> 16;
      sighdr[16 + 16 * 3 + 2] = written >> 8;
      sighdr[16 + 16 * 3 + 3] = written;
      memcpy(&sighdr[16 + 16 * 3 + 4], paymd5res, 16);
      if (write(fd, sighdr, sizeof(sighdr)) != sizeof(sighdr))
	{
	  fprintf(stderr, "sig write failed\n");
	  exit(1);
	}
    }
  if (strcmp(d->name, "-") != 0 && close(fd) != 0)
    {
      fprintf(stderr, "payload write failed\n");
      exit(1);
    }
}
