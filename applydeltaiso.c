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

#include "util.h"
#include "md5.h"
#include "cfile.h"

#define BLKSIZE 8192

unsigned int get4(FILE *fp)
{
  unsigned char dd[4];
  if (fread(dd, 4, 1, fp) != 1)
    {
      perror("fread");
      exit(1);
    }
  return dd[0] << 24 | dd[1] << 16 | dd[2] << 8 | dd[3];
}

unsigned int cget4(struct cfile *fp)
{
  unsigned char dd[4];
  if (fp->read(fp, dd, 4) != 4)
    {
      perror("cget4 read");
      exit(1);
    }
  return dd[0] << 24 | dd[1] << 16 | dd[2] << 8 | dd[3];
}

void
filloutdata(FILE *fpold, unsigned char *data, unsigned int *nmp, int nmpn)
{
  unsigned char *dp;
  int i;

  dp = data;
  for (i = 0; i < 2 * nmpn + 1; i += 2)
    {
      if (nmp[i])
	{
	  if (fread(dp, nmp[i], 1, fpold) != 1)
	    {
	      perror("fread");
	      exit(1);
	    }
	  dp += nmp[i];
	}
      if (nmp[i + 1])
	{
	  if (fseeko64(fpold, (off64_t)nmp[i + 1], SEEK_CUR))
	    {
	      perror("fseeko64");
	      exit(1);
	    }
	}
    }
}

void applydelta(FILE *fpold, struct cfile *ocf, struct cfile *cf, unsigned char *outdata, unsigned int outlen, unsigned int *nmp, int nmpn);

void
processrpm(FILE *fpold, struct cfile *ocf, struct cfile *cf, unsigned int *nmp, int nmpn)
{
  int rpmn, i;
  unsigned int ctype;
  off64_t o;
  struct cfile *opcf, *npcf;
  unsigned char *paydata;
  unsigned int paylen;
  unsigned char namebuf[256];

  if (cf->read(cf, namebuf, 2) != 2)
    {
      perror("rpm namebuf read");
      exit(1);
    }
  ctype = namebuf[0];
  if (ctype < 254)
    ctype = CFILE_MKCOMP(ctype & 15, ctype >> 4);
  i = namebuf[1];
  if (cf->read(cf, namebuf, i) != i)
    {
      perror("rpm namebuf read");
      exit(1);
    }
  namebuf[i] = 0;
  if (ctype == 255)
    {
      unsigned int len, l;
      unsigned char buf[8192];

      printf("%s: verbatim copy\n", namebuf);
      len = cget4(cf);
      while (len)
	{
	  l = len > sizeof(buf) ? sizeof(buf) : len;
	  if (cf->read(cf, buf, l) != l)
	    {
	      perror("verbatim copy read");
	      exit(1);
	    }
	  if (ocf->write(ocf, buf, l) != l)
	    {
	      perror("verbatim copy write");
	      exit(1);
            }
	  len -= l;
	}
      return;
    }
  if (ctype == 254)
    printf("%s: copying unchanged payload\n", namebuf);
  else
    printf("%s (%s): applying delta\n", namebuf, cfile_comp2str(ctype));
  rpmn = cget4(cf);
  if (rpmn < 0 || rpmn >= nmpn)
    {
      fprintf(stderr, "illegal rpm descriptor %d (max %d), ctype was %d\n", rpmn, nmpn, ctype);
      exit(1);
    }
  o = 0;
  for (i = 0; i < 2 * rpmn + 1; i++)
    o += nmp[i];
  if (fseeko64(fpold, o, SEEK_SET))
    {
      perror("fseeko64");
      exit(1);
    }
  if (ctype == 254)
    {
      unsigned int len, l;
      unsigned char buf[8192];

      len = nmp[i];
      while (len)
	{
	  l = len > sizeof(buf) ? sizeof(buf) : len;
	  l = fread(buf, 1, l, fpold);
	  if (l <= 0 && ferror(fpold))
	    {
	      perror("unchanged copy read");
	      exit(1);
	    }
	  if (ocf->write(ocf, buf, l) != l)
	    {
	      perror("unchanged copy write");
	      exit(1);
            }
	  len -= l;
	}
      return;
    }
  paylen = cget4(cf);
  paydata = xmalloc(paylen);
  opcf = cfile_open(CFILE_OPEN_RD, CFILE_IO_FILE, fpold, CFILE_COMP_XX, nmp[i], 0, 0);
  if (!opcf)
    {
      fprintf(stderr, "payload open failed\n");
      exit(1);
    }
  if (opcf->read(opcf, paydata, paylen) != paylen)
    {
      fprintf(stderr, "payload uncompress error\n");
      exit(1);
    }
  /* ignore extra bytes as we did not read until EOF */
  if (opcf->close(opcf) == -1)
    {
      fprintf(stderr, "payload uncompress error (extra bytes)\n");
      exit(1);
    }
  npcf = cfile_open(CFILE_OPEN_WR, CFILE_IO_CFILE, ocf, ctype, CFILE_LEN_UNLIMITED, 0, 0);
  if (!npcf)
    {
      fprintf(stderr, "new payload open failed\n");
      exit(1);
    }
  applydelta(0, npcf, cf, paydata, paylen, 0, 0);
  if (npcf->close(npcf) == -1)
    {
      fprintf(stderr, "new payload compression error\n");
      exit(1);
    }
  free(paydata);
}

/* apply delta to paydata/paylen, write result to ocf/fbnew */
void
applydelta(FILE *fpold, struct cfile *ocf, struct cfile *cf, unsigned char *outdata, unsigned int outlen, unsigned int *nmp, int nmpn)
{
  unsigned int inn;
  unsigned int *in;
  unsigned int outn, on;
  unsigned int *out;
  unsigned int *inp;
  unsigned int *outp;
  unsigned char *addbz2 = 0;
  unsigned int addbz2len = 0;
  bz_stream addbz2strm;
  unsigned char *b;
  unsigned char buf[BLKSIZE];
  unsigned int off, len, l;
  unsigned int newl;
  int i;

  /* oldl = cget4(cf); already done in called */
  newl = cget4(cf);
  inn = cget4(cf);
  outn = cget4(cf);
  in = xmalloc2(inn, 2 * sizeof(unsigned int));
  out = xmalloc2(outn, 2 * sizeof(unsigned int));
  for (i = 0; i < inn; i++)
    in[2 * i] = cget4(cf);
  for (i = 0; i < inn; i++)
    in[2 * i + 1] = cget4(cf);
  for (i = 0; i < outn; i++)
    out[2 * i] = cget4(cf);
  for (i = 0; i < outn; i++)
    out[2 * i + 1] = cget4(cf);
  addbz2len = cget4(cf);
  if (addbz2len)
    {
      addbz2 = xmalloc(addbz2len);
      if (cf->read(cf, addbz2, addbz2len) != addbz2len)
	{
	  perror("addblk read");
	  exit(1);
	}
    }
  off = 0;
  on = 0;
  for (i = 0; i < inn; i++)
    on += in[2 * i];
  if (on > outn)
    {
      fprintf(stderr, "corrupt delta instructions (out sum %d > %d)\n", on, outn);
      exit(1);
    }
  off = 0;
  for (i = 0; i < outn; i++)
    {
      if (out[2 * i] & 0x80000000)
	off -= out[2 * i] ^ 0x80000000;
      else
	off += out[2 * i];
      if (off > outlen)
	{
	  fprintf(stderr, "corrupt delta instructions (outdata off %d > %d)\n", off, outlen);
	  exit(1);
	}
      out[2 * i] = off;
      off += out[2 * i + 1];
      if (off < 1 || off > outlen)
	{
	  fprintf(stderr, "corrupt delta instructions (outdata off + len %d > %d)\n", off, outlen);
	  exit(1);
	}
    }
  if (addbz2len)
    {
      addbz2strm.bzalloc = NULL;
      addbz2strm.bzfree = NULL;
      addbz2strm.opaque = NULL;
      if (BZ2_bzDecompressInit(&addbz2strm, 0, 0) != BZ_OK)
        {
          fprintf(stderr, "addbz2: BZ2_bzDecompressInit error\n");
          exit(1);
        }
      addbz2strm.next_in = (char *)addbz2;
      addbz2strm.avail_in = addbz2len;
    }

  inp = in;
  outp = out;
  while (inn > 0)
    {
      for (on = *inp++; on > 0; )
	{
	  off = *outp++;
	  len = *outp++;
	  on--;
	  while (len > 0)
	    {
	      b = outdata + off;
	      l = len > BLKSIZE ? BLKSIZE : len;
	      if (addbz2len)
		{
		  addbz2strm.next_out = (char *)buf;
		  addbz2strm.avail_out = l;
		  i = BZ2_bzDecompress(&addbz2strm);
                  if (addbz2strm.avail_out != 0)
		    {
		      fprintf(stderr, "addbz2: BZ2_bzDecompress error\n");
		      exit(1);
		    }
		  for (i = 0; i < l; i++)
		    buf[i] += b[i];
		  b = buf;
		}
	      if (ocf->write(ocf, b, l) != l)
		{
		  perror("cf write");
		  exit(1);
		}
	      len -= l;
	      off += l;
	    }
	}
      len = *inp++;
      inn--;
      if (len == 0xffffffff && nmp)
	{
	  processrpm(fpold, ocf, cf, nmp, nmpn);
	}
      else
	{
	  while (len > 0)
	    {
	      l = len > sizeof(buf) ? sizeof(buf) : len;
	      if (cf->read(cf, buf, l) != l)
		{
		  fprintf(stderr, "indata read %d bytes failed\n", l);
		  exit(1);
		}
	      if (ocf->write(ocf, buf, l) != l)
		{
		  perror("cf write");
		  exit(1);
		}
	      len -= l;
	    }
	}
    }
  if (addbz2len)
    BZ2_bzDecompressEnd(&addbz2strm);
  in = xfree(in);
  out = xfree(out);
}

int main(int argc, char **argv)
{
  FILE *fpold, *fpnew, *fpdlt;
  struct cfile *cfnew;
  int vers;
  unsigned char md5res[16];
  unsigned char targetres[16];
  MD5_CTX md5;
  unsigned int nmpn;
  unsigned int *nmp;
  struct cfile *cf;
  int i;
  unsigned char *outdata;
  unsigned int outlen, oldl;

  if (argc != 4)
    {
      fprintf(stderr, "usage: applydeltaiso <oldiso> <deltaiso> <newiso>\n");
      exit(1);
    }
  if ((fpold = fopen64(argv[1], "r")) == 0)
    {
      perror(argv[1]);
      exit(1);
    }
  if ((fpdlt = fopen64(argv[2], "r")) == 0)
    {
      perror(argv[2]);
      exit(1);
    }
  if (get4(fpdlt) != ('D' << 24 | 'I' << 16 | 'S' << 8 | 'O'))
    {
      fprintf(stderr, "%s: not a delta iso\n", argv[2]);
      exit(1);
    }
  vers = get4(fpdlt);
  if (vers != 1 && vers != 2)
    {
      fprintf(stderr, "%s: unsupported version V%d\n", argv[2], vers);
      exit(1);
    }
  /* switch to compression */
  cf = cfile_open(CFILE_OPEN_RD, CFILE_IO_FILE, fpdlt, CFILE_COMP_BZ, CFILE_LEN_UNLIMITED, 0, 0);
  nmpn = cget4(cf);
  nmp = xmalloc2(nmpn + 1, 2 * sizeof(*nmp));
  for (i = 0; i < nmpn * 2 + 1; i++)
    nmp[i] = cget4(cf);
  nmp[i] = 0;

  outlen = 0;
  for (i = 0; i < nmpn * 2 + 1; i += 2)
    outlen += nmp[i];
  printf("reading %d bytes from old iso...", outlen);
  fflush(stdout);
  outdata = xmalloc(outlen);
  filloutdata(fpold, outdata, nmp, nmpn);
  printf("done\n");

  if ((fpnew = fopen64(argv[3], "w")) == 0)
    {
      perror(argv[3]);
      exit(1);
    }
  rpmMD5Init(&md5);
  if ((cfnew = cfile_open(CFILE_OPEN_WR, CFILE_IO_FILE, fpnew, CFILE_COMP_UN, CFILE_LEN_UNLIMITED, (cfile_ctxup)rpmMD5Update, &md5)) == 0)
    {
      fprintf(stderr, "cfile open iso failed\n");
      exit(1);
    }
  oldl = cget4(cf);
  if (oldl != outlen)
    {
      fprintf(stderr, "diff outlen mismatch: %d %d\n", oldl, outlen);
      exit(1);
    }
  applydelta(fpold, cfnew, cf, outdata, outlen, nmp, nmpn);
  if (cfnew->close(cfnew) == -1)
    {
      fprintf(stderr, "cfile close iso failed\n");
      exit(1);
    }
  if (fclose(fpnew))
    {
      perror("iso fclose");
      exit(1);
    }
  rpmMD5Final(md5res, &md5);
  outdata = xfree(outdata);
  if (cf->read(cf, targetres, 16) != 16)
    {
      perror("md5 read");
      exit(1);
    }
  if (cf->close(cf) == -1)
    {
      perror("delta close");
      exit(1);
    }
  if (memcmp(md5res, targetres, 16))
    {
      fprintf(stderr, "md5sum mismatch, iso is corrupt\n");
      exit(1);
    }
  printf("iso successfully re-created, md5sum: ");
  for (i = 0; i < 16; i++)
     printf("%02x", md5res[i]);
  printf("\n");
  exit(0);
}

