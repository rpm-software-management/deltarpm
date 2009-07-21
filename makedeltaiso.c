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
#include <stdint.h>

#include <zlib.h>
#include <bzlib.h>
#include <lzma.h>

#include "rpmoffs.h"
#include "delta.h"
#include "util.h"
#include "md5.h"
#include "cfile.h"

double targetsize;
double writtensize;

unsigned int readiso(FILE *fp, struct rpmpay *pay, int payn, unsigned char **isop)
{
  off64_t size;
  off64_t skipsum;
  off64_t last;
  int i;
  unsigned char *iso;
  unsigned int l, p, lastl;
  char *lastn;

  last = 0;
  lastl = 0;
  skipsum = 0;
  lastn = "<start>";
  for (i = 0; i < payn; i++)
    {
      if (pay[i].o == last)
	{
	  if (pay[i].l != lastl)
	    {
	      fprintf(stderr, "files at same pos with different sizes\n");
	      exit(1);
	    }
	  continue;
	}
      if (last + lastl > pay[i].o)
	{
	  fprintf(stderr, "files overlap %s %s %lld %d %lld\n", lastn, pay[i].name, (long long int)last, lastl, (long long int)pay[i].o);
	  exit(1);
	}
      last = pay[i].o;
      lastl = pay[i].l;
      lastn = pay[i].name;
      skipsum += pay[i].l;
    }
  if (fseeko64(fp, (off64_t)0, SEEK_END) != 0)
    {
      perror("fseeko64");
      exit(1);
    }
  size = ftello64(fp);
  if (size < skipsum)
    {
      fprintf(stderr, "size < skipsum\n");
      exit(1);
    }
  if (fseeko64(fp, (off64_t)0, SEEK_SET) != 0)
    {
      perror("fseeko64");
      exit(1);
    }
  if (size - skipsum >= 0x80000000)
    {
      fprintf(stderr, "remaining size too big: %lld\n", (long long int)(size - skipsum));
      exit(1);
    }
  l = size - skipsum;
  if ((iso = malloc(l)) == 0)
    {
      fprintf(stderr, "out of mem for iso (%d bytes)", l);
      exit(1);
    }
  last = 0;
  lastl = 0;
  p = 0;
  pay[payn].o = size;
  for (i = 0; i <= payn; i++)
    {
      if (pay[i].o == last)
	continue;
      if (fread(iso + p, pay[i].o - (last + lastl), 1, fp) != 1)
	{
	  fprintf(stderr, "read error\n");
	  exit(1);
	}
      pay[i].x = p;
      pay[i].lx = pay[i].o - (last + lastl);
      p += pay[i].o - (last + lastl);
      last = pay[i].o;
      lastl = pay[i].l;
      if (fseeko64(fp, pay[i].o + pay[i].l, SEEK_SET))
	{
	  perror("fseeko64");
	  exit(1);
	}
    }
  if (p != l)
    {
      fprintf(stderr, "internal error %d %d\n", p, l);
      exit(1);
    }
  *isop = iso;
  return l;
}

void
recode_instr(struct instr *instr, int instrlen, unsigned int **b1p, int *nb1p, unsigned int **b2p, int *nb2p, struct rpmpay *pay, int payn)
{
  unsigned int *b1;
  int nb1;
  unsigned int *b2;
  int nb2;
  int i, j;
  int lastoff;
  unsigned int x1, x2, x3, x4;
  unsigned int left;
  int payp;

  b1 = b2 = 0; 
  nb1 = nb2 = 0;
  j = 0;  
  lastoff = 0;
  left = pay && payn ? pay[0].lx : 0;
  payp = 0;
  for (i = 0; i < instrlen; i++)
    {
      x1 = instr[i].copyout;
      x2 = instr[i].copyin;
      x3 = instr[i].copyoutoff;
      x4 = instr[i].copyinoff;
retry:
      if (!x1)
        {
          if (!x2)
            continue;
        }
      if (x1)
        {
          if ((nb2 & 15) == 0)
            b2 = xrealloc2(b2, nb2 + 16, 2 * sizeof(unsigned int));
          if (lastoff <= x3)
            b2[2 * nb2] = x3 - lastoff;
          else
            b2[2 * nb2] = (lastoff - x3) | 0x80000000;
          if (left && x1 >= left)
	    {
	      b2[2 * nb2 + 1] = left;
	      nb2++;
	      j++;
	      x3 = lastoff = x3 + left;
	      x1 -= left;
	      if ((nb1 & 15) == 0)
		b1 = xrealloc2(b1, nb1 + 16, 3 * sizeof(unsigned int));
	      b1[3 * nb1] = j;
	      b1[3 * nb1 + 1] = 0xffffffff;
	      b1[3 * nb1 + 2] = payp;
	      nb1++;
	      j = 0;
	      left = 0;
	      while (payp < payn && pay[++payp].x == 0)
		;
	      if (payp < payn)
		left = pay[payp].lx;
	      goto retry;
	    }
          else
	    {
	      b2[2 * nb2 + 1] = x1;
	      nb2++;
	      j++;
	      x3 = lastoff = x3 + x1;
	      if (left)
	        left -= x1;
	    }
        }
      if (x2)
        {
          if (left && x2 >= left)
	    {
	      if ((nb1 & 15) == 0)
		b1 = xrealloc2(b1, nb1 + 16, 3 * sizeof(unsigned int));
	      b1[3 * nb1] = j;
	      b1[3 * nb1 + 1] = left;
	      b1[3 * nb1 + 2] = x4;
	      nb1++;
	      j = 0;
	      x2 -= left;
	      x4 += left;
	      if ((nb1 & 15) == 0)
		b1 = xrealloc2(b1, nb1 + 16, 3 * sizeof(unsigned int));
	      b1[3 * nb1] = 0;
	      b1[3 * nb1 + 1] = 0xffffffff;
	      b1[3 * nb1 + 2] = payp;
	      nb1++;
	      left = 0;
	      while (payp < payn && pay[++payp].x == 0)
		;
	      if (payp < payn)
		left = pay[payp].lx;
	      x1 = 0;
	      goto retry;
	    }
          if ((nb1 & 15) == 0)
            b1 = xrealloc2(b1, nb1 + 16, 3 * sizeof(unsigned int));
          b1[3 * nb1] = j;
          b1[3 * nb1 + 1] = x2;
          b1[3 * nb1 + 2] = x4;
          nb1++;
          j = 0;
	  if (left)
	    left -= x2;
        }
    }
  if (left || payp != payn)
    {
      fprintf(stderr, "oops, left = %d %d %d\n", left, payp, payn);
      exit(1);
    }
  if (j)
    {
      if ((nb1 & 15) == 0)
        b1 = xrealloc2(b1, nb1 + 16, 3 * sizeof(unsigned int));
      b1[3 * nb1] = j;
      b1[3 * nb1 + 1] = 0;
      b1[3 * nb1 + 2] = 0;
      nb1++;
    }
  *b1p = b1;
  *nb1p = nb1;
  *b2p = b2;
  *nb2p = nb2;
}

void
bzput4(struct cfile *fp, unsigned int d)
{
  unsigned char dd[4];
  dd[0] = d >> 24;
  dd[1] = d >> 16;
  dd[2] = d >> 8;
  dd[3] = d;
  if (fp->write(fp, dd, 4) != 4)
    {
      perror("bzwrite");
      exit(1);
    }
}

void
put4(FILE *fp, unsigned int d)
{
  unsigned char dd[4];
  dd[0] = d >> 24;
  dd[1] = d >> 16;
  dd[2] = d >> 8;
  dd[3] = d;
  if (fwrite(dd, 4, 1, fp) != 1)
    {
      perror("fwrite");
      exit(1);
    }
}

void diffit(struct cfile *fpout, FILE *fpold, FILE *fpnew, unsigned char *old, unsigned int oldl, unsigned char *new, int newl, struct rpmpay *newpays, int newpayn, struct rpmpay *oldpays, int oldpayn, MD5_CTX *ctx);

unsigned int payread(FILE *fp, off64_t off, unsigned int len, unsigned char **pp, MD5_CTX *ctx, unsigned char *namebuf)
{
  int l, r;
  struct cfile *cfile;

  if (fseeko64(fp, off, SEEK_SET) != 0)
    {
      perror("fseeko");
      exit(1);
    }
  cfile = cfile_open(CFILE_OPEN_RD, CFILE_IO_FILE, fp, CFILE_COMP_XX, len, ctx ? (cfile_ctxup)rpmMD5Update : 0, ctx);
  if (!cfile)
    {
      fprintf(stderr, "cfile open failed\n");
      exit(1);
    }
  if (namebuf)
    {
      cfile_detect_rsync(cfile);
      namebuf[0] = cfile->comp;
    }
  l = cfile_copy(cfile, cfile_open(CFILE_OPEN_WR, CFILE_IO_ALLOC, pp, CFILE_COMP_UN, CFILE_LEN_UNLIMITED, 0, 0), CFILE_COPY_CLOSE_OUT);
  if (l == -1)
    {
      fprintf(stderr, "cfile_copy failed\n");
      exit(1);
    }
  r = cfile->close(cfile);
  if (r)
    {
      fprintf(stderr, "cfile not used up (%d bytes left)\n", r);
      exit(1);
    }
  return l;
}

void
processrpm(struct cfile *fpout, FILE *fpold, FILE *fpnew, struct rpmpay *pay, struct rpmpay *oldpays, int oldpayn, MD5_CTX *ctx)
{
  struct rpmpay *oldpay;
  int i, n;
  unsigned int l, newl, oldl;
  unsigned char *new, *old;
  unsigned char namebuf[258];

  oldpay = 0;
  for (i = 0; i < oldpayn; i++)
    if (!strcmp(oldpays[i].name, pay->name))
      {
        oldpay = oldpays + i;
        break;
      }
  l = strlen(pay->name);
  if (l > 255)
    l = 255;
  namebuf[0] = 255;
  namebuf[1] = l;
  memcpy(namebuf + 2, pay->name, l);
  namebuf[l + 2] = 0;
  targetsize += pay->l;
  if (!oldpay)
    {
      printf("%s: not found in old iso...", pay->name);
      if (fpout->write(fpout, namebuf, l + 2) != l + 2)
	{
	  perror("namebuf write");
	  exit(1);
	}
      bzput4(fpout, pay->l);
      if (fseeko64(fpnew, pay->o, SEEK_SET) != 0)
	{
	  perror("fseeko");
	  exit(1);
	}
      if (cfile_copy(cfile_open(CFILE_OPEN_RD, CFILE_IO_FILE, fpnew, CFILE_COMP_UN, pay->l, (cfile_ctxup)rpmMD5Update, ctx), fpout, CFILE_COPY_CLOSE_IN) != 0)
	{
	  fprintf(stderr, "cfile_copy failed\n");
	  exit(1);
	}
    }
  else
    {
      n = 0;
      for (i = 0; i < oldpayn; i++)
	if (i == 0 || oldpays[i].x != 0)
	  {
	    if (oldpays[i].o == oldpay->o)
	      break;
	    else
	      n++;
	  }
      if (i == oldpayn)
	{
	  fprintf(stderr, "internal error\n");
	  exit(1);
	}
      if (oldpay->l != oldpays[i].l)
	{
	  fprintf(stderr, "internal error, length mismatch %d %d\n", oldpay->l, oldpays[i].l);
	  exit(1);
	}
      /* payread will fix namebuf[0] */
      newl = payread(fpnew, pay->o, pay->l, &new, ctx, namebuf);
      oldl = payread(fpold, oldpay->o, oldpay->l, &old, 0, 0);
      if (newl == oldl && pay->l == oldpay->l && !memcmp(new, old, newl))
	{
	  printf("%s: unchanged...", namebuf + 2);
	  namebuf[0] = 254;
	}
      else
	{
	  int comp = cfile_setlevel(namebuf[0], pay->level);
	  printf("%s (%s): creating delta...", namebuf + 2, cfile_comp2str(comp));
	  namebuf[0] = CFILE_COMPALGO(comp) | (CFILE_COMPLEVEL(comp) << 4);	/* argh! */
	}
      fflush(stdout);
      if (fpout->write(fpout, namebuf, l + 2) != l + 2)
	{
	  perror("namebuf write");
	  exit(1);
	}
      bzput4(fpout, n);		/* offset id */
      if (namebuf[0] == 254)
        free(old);
      else
        diffit(fpout, 0, 0, old, oldl, new, newl, 0, 0, 0, 0, 0);
      old = 0;
      oldl = 0;
      free(new);
      new = 0;
      newl = 0;
    }
  writtensize += fpout->bytes;
  fpout->bytes = 0;
  printf("%4.1f%%\n", writtensize * 100 / targetsize);
}

/* frees old! */
void diffit(struct cfile *fpout, FILE *fpold, FILE *fpnew, unsigned char *old, unsigned int oldl, unsigned char *new, int newl, struct rpmpay *newpays, int newpayn, struct rpmpay *oldpays, int oldpayn, MD5_CTX *ctx)
{
  unsigned int *b1;
  int nb1;
  unsigned int *b2;
  int nb2;
  struct instr *instr = 0;
  int instrlen = 0;
  unsigned char *addblk = 0;
  unsigned int addblklen = 0;
  int i, j, b2i;
  unsigned int off;

  mkdiff(DELTAMODE_HASH, old, oldl, new, newl, &instr, &instrlen, 0, 0, &addblk, &addblklen, 0, 0);
  free(old);
  old = 0;
  recode_instr(instr, instrlen, &b1, &nb1, &b2, &nb2, newpays, newpayn);
  free(instr);
  instr = 0;
  instrlen = 0;
  bzput4(fpout, oldl);
  bzput4(fpout, newl);
  bzput4(fpout, nb1);
  bzput4(fpout, nb2);
  for (i = 0; i < nb1; i++)
    bzput4(fpout, b1[3 * i]);
  for (i = 0; i < nb1; i++)
    bzput4(fpout, b1[3 * i + 1]);
  for (i = 0; i < nb2; i++)
    bzput4(fpout, b2[2 * i]);
  for (i = 0; i < nb2; i++)
    bzput4(fpout, b2[2 * i + 1]);

  /* write add section */
  bzput4(fpout, addblklen);
  if (addblklen && fpout->write(fpout, addblk, addblklen) != addblklen)
    {
      perror("bzwrite");
      exit(1);
    }
  if (addblk)
    free(addblk);

  /* write data section */
  b2i = 0;
  off = 0;
  for (i = 0; i < nb1; i++)
    {
      if (ctx)
	{
	  for (j = 0; j < b1[3 * i]; j++, b2i++)
	    {
	      if (b2[2 * b2i + 1])
	        rpmMD5Update(ctx, new + off, b2[2 * b2i + 1]);
	      off += b2[2 * b2i + 1];
	    }
	}
      if (b1[3 * i + 1] == 0xffffffff)
	{
	  processrpm(fpout, fpold, fpnew, newpays + b1[3 * i + 2], oldpays, oldpayn, ctx);
	}
      else if (b1[3 * i + 1])
	{
	  if (ctx)
	    {
	      if (off != b1[3 * i + 2])
		{
		  fprintf(stderr, "internal error: off mismatch %d %d\n", off, b1[3 * i + 2]);
		  exit(1);
		}
	      rpmMD5Update(ctx, new + off, b1[3 * i + 1]);
	      off += b1[3 * i + 1];
	    }
	  if (fpout->write(fpout, new + b1[3 * i + 2], b1[3 * i + 1]) != b1[3 * i + 1])
	    {
	      perror("bzwrite");
	      exit(1);
	    }
	}
    }
  free(b1);
  free(b2);
}

int
main(int argc, char **argv)
{
  FILE *fpold, *fpnew, *fpout;
  unsigned int oldisolen;
  unsigned int newisolen;
  unsigned char *oldiso;
  unsigned char *newiso;
  struct rpmpay *oldpays = 0;
  int oldpayn = 0;
  struct rpmpay *newpays = 0;
  int newpayn = 0;
  int i, n;
  struct cfile *bf;
  MD5_CTX targetmd5;
  unsigned char targetmd5res[16];

  if (argc != 4)
    {
      fprintf(stderr, "usage: makedeltaiso <oldiso> <newiso> <deltaiso>\n");
      exit(1);
    }
  if ((fpold = fopen64(argv[1], "r")) == 0)
    {
      perror(argv[1]);
      exit(1);
    }
  if ((fpnew = fopen64(argv[2], "r")) == 0)
    {
      perror(argv[2]);
      exit(1);
    }
  oldpayn = rpmoffs(fpold, argv[1], &oldpays);
  printf("%s: %d rpms\n", argv[1], oldpayn);
  newpayn = rpmoffs(fpnew, argv[2], &newpays);
  printf("%s: %d rpms\n", argv[2], newpayn);
  if ((fpout = fopen64(argv[3], "w")) == 0)
    {
      perror(argv[3]);
      exit(1);
    }
  printf("reading old iso (omitting payloads)\n");
  oldisolen = readiso(fpold, oldpays, oldpayn, &oldiso);
  printf("size without payloads is %d bytes\n", oldisolen);
  printf("reading new iso (omitting payloads)\n");
  newisolen = readiso(fpnew, newpays, newpayn, &newiso);
  printf("size without payloads is %d bytes\n", newisolen);
  targetsize = newisolen;

  putc('D', fpout);
  putc('I', fpout);
  putc('S', fpout);
  putc('O', fpout);
  put4(fpout, 2);
  if ((bf = cfile_open(CFILE_OPEN_WR, CFILE_IO_FILE, fpout, CFILE_COMP_BZ, CFILE_LEN_UNLIMITED, 0, 0)) == 0)
    {
      fprintf(stderr, "cfile wopen failed\n");
      exit(1);
    }
  /* write old map */
  n = 0;
  for (i = 0; i < oldpayn; i++)
    if (i == 0 || oldpays[i].x)
      n++;
  bzput4(bf, n);
  for (i = 0; i < oldpayn; i++)
    if (i == 0 || oldpays[i].x)
      {
        bzput4(bf, oldpays[i].lx);
        bzput4(bf, oldpays[i].l);
      }
  bzput4(bf, oldpays[i].lx);

  printf("creating iso diff\n");
  rpmMD5Init(&targetmd5);
  diffit(bf, fpold, fpnew, oldiso, oldisolen, newiso, newisolen, newpays, newpayn, oldpays, oldpayn, &targetmd5);
  rpmMD5Final(targetmd5res, &targetmd5);
  oldiso = 0;
  oldisolen = 0;
  free(newiso);
  newiso = 0;
  newisolen = 0;
  writtensize += bf->bytes;
  bf->bytes = 0;
  printf("iso diff done, final compression: %4.1f%%\n", writtensize * 100 / targetsize);
  if (bf->write(bf, targetmd5res, 16) != 16)
    {
      perror("md5sum write");
      exit(1);
    }
  if (bf->close(bf) == -1)
    {
      perror("cfile close");
      exit(1);
    }
  if (fclose(fpout))
    {
      perror("fclose");
      exit(1);
    }
  printf("iso md5sum is: ");
  for (i = 0; i < 16; i++)
    printf("%02x", targetmd5res[i]);
  printf("\n");
  for (i = 0; i < oldpayn; i++)
    free(oldpays[i].name);
  free(oldpays);
  for (i = 0; i < newpayn; i++)
    free(newpays[i].name);
  free(newpays);
  exit(0);
}
