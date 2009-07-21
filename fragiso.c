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
#include <unistd.h>

#include <zlib.h>
#include <lzma.h>
#include <bzlib.h>

#include "rpmhead.h"
#include "md5.h"
#include "util.h"
#include "cfile.h"

struct rpmpay {
  char *name;
  unsigned int x;
  unsigned int lx;
  off64_t o;
  unsigned int l;
  unsigned char lmd5[16];
  unsigned char hmd5[16];
};

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
addrpm(char *name, off64_t o, unsigned int l, unsigned char *lmd5, unsigned char *hmd5)
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
  if (lmd5)
    memcpy(rpmpays[rpmpayn].lmd5, lmd5, 16);
  else
    memset(rpmpays[rpmpayn].lmd5, 0, 16);
  if (hmd5)
    memcpy(rpmpays[rpmpayn].hmd5, hmd5, 16);
  else
    memset(rpmpays[rpmpayn].hmd5, 0, 16);
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

void
readrpm(char *name, FILE *fp, unsigned int filepos, unsigned int filelen)
{
  static unsigned int rpmbalen;
  static unsigned char *rpmb;
  int rpmblen;
  int len, hcnt, hdcnt, hoffset;
  struct rpmhead *h, *sigh;
  char *rpmn, *rpma;
  unsigned char lmd5[16], *hmd5;
  char nbuf[256 * 3];
  char *suf;
  MD5_CTX ctx;
  unsigned int filepos2 = filepos;

  len = strlen(name);
  suf = "";
  if (len > 10 && !strcmp(name + len - 10, ".delta.rpm"))
    suf = ".delta";
  else if (len > 10 && !strcmp(name + len - 10, ".patch.rpm"))
    suf = ".patch";
  
  if (!rpmb)
    {
      rpmbalen += 0x800 * 4;
      rpmb = xrealloc(rpmb, rpmbalen);
    }
  readblk(fp, rpmb, filepos++);
  rpmblen = 0x800;

  if (get4(rpmb) != 0xdbeeabed)
    return;	/* not really a rpm */

  if (get4(rpmb + 0x60) != 0x01e8ad8e)
    {
      fprintf(stderr, "bad rpm (bad sigheader): %s\n", name);
      exit(1);
    }
  hcnt = get4n(rpmb + 0x68);
  hdcnt = get4n(rpmb + 0x6c);
  if ((hdcnt & 7) != 0)
   hdcnt += 8 - (hdcnt & 7);
  len = 0x60 + 16 + hcnt * 16 + hdcnt + 16;
  if (len > filelen)
    {
      fprintf(stderr, "bad rpm (EOF): %s\n", name);
      exit(1);
    }
  while (rpmblen < len)
    {
      if (rpmblen + 0x800 > rpmbalen)
	{
	  rpmbalen += 0x800 * 4;
	  rpmb = xrealloc(rpmb, rpmbalen);
	}
      readblk(fp, rpmb + rpmblen, filepos++);
      rpmblen += 0x800;
    }
  sigh = readhead_buf(rpmb + 0x60, len - 16, 1);
  if (!sigh)
    {
      fprintf(stderr, "bad rpm (bad sigh): %s\n", name);
      exit(1);
    }
  hoffset = len - 16;
  if (get4(rpmb + hoffset) != 0x01e8ad8e)
    {
      fprintf(stderr, "bad rpm (bad header): %s\n", name);
      exit(1);
    }
  hcnt = get4n(rpmb + hoffset + 8);
  hdcnt = get4n(rpmb + hoffset + 12);
  len += hcnt * 16 + hdcnt;
  if (len > filelen)
    {
      fprintf(stderr, "bad rpm (EOF): %s\n", name);
      exit(1);
    }
  while (rpmblen < len)
    {
      if (rpmblen + 0x800 > rpmbalen)
	{
	  rpmbalen += 0x800 * 4;
	  rpmb = xrealloc(rpmb, rpmbalen);
	}
      readblk(fp, rpmb + rpmblen, filepos++);
      rpmblen += 0x800;
    }
  h = readhead_buf(rpmb + hoffset, 16 + hcnt * 16 + hdcnt, 0);
  if (!h)
    {
      fprintf(stderr, "bad rpm (bad h): %s\n", name);
      exit(1);
    }
  /* ok, all header are read in, extract information */
  rpmn = headstring(h, TAG_NAME);
  if (!rpmn)
    {
      fprintf(stderr, "bad rpm (header contains no name): %s\n", name);
      exit(1);
    }
  rpma = headstring(h, TAG_ARCH);
  if (!rpma)
    {
      fprintf(stderr, "bad rpm (header contains no arch): %s\n", name);
      exit(1);
    }
  if (strlen(rpmn) > 256 || strchr(rpmn, ' ') || strchr(rpmn, '/') ||  strchr(rpmn, '\n'))
    rpmn = "unknown";
  if (!headstring(h, TAG_SOURCERPM))
    {
      if (headtagtype(h, TAG_NOSOURCE) || headtagtype(h, TAG_NOPATCH))
	rpma = "nosrc";
      else
	rpma = "src";
    }
  if (strlen(rpma) > 256 || strchr(rpma, ' ') || strchr(rpma, '/') ||  strchr(rpma, '\n'))
    rpma = "unknown";
  hmd5 = headbin(sigh, SIGTAG_MD5, 16);
  if (!hmd5)
    {
      fprintf(stderr, "bad rpm (signature contains no md5 entry): %s\n", name);
      exit(1);
    }
  sprintf(nbuf, "%s.%s%s", rpmn, rpma, suf);
  rpmMD5Init(&ctx);
  rpmMD5Update(&ctx, rpmb, hoffset);
  rpmMD5Final(lmd5, &ctx);
  addrpm(nbuf, 0x800 * (off64_t)filepos2, filelen, lmd5, hmd5);
  h = xfree(h);
  sigh = xfree(sigh);
}

int
rpmoffs(FILE *fp, char *isoname, struct rpmpay **retp)
{
  unsigned char blk[0x800];
  unsigned char blk2[0x800];
  unsigned char name[256];
  int namel;
  unsigned int filepos, filelen;
  unsigned char *pt, *ep;
  int i, j, l, nl, el, nml, nmf;

  unsigned int path_table_size;
  unsigned int path_table_pos;
  unsigned int dirpos, dirlen;
  int sp_bytes_skip = 0;
  unsigned int ce_blk;
  unsigned int ce_off;
  unsigned int ce_len;

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
	  if (filelen < 0x70 || (strcmp((char *)name + namel - 4, ".rpm") && strcmp((char *)name + namel - 4, ".spm")))
	    continue;
          readrpm((char *)name, fp, filepos, filelen);

#if 0
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
#endif
	}
    }
  sortrpm();
  addrpm(0, 0, 0, 0, 0);
  i = rpmpayn - 1;
  *retp = rpmpays;
  rpmpayn = 0;
  rpmpays = 0;
  return i;
}

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

static void
write64(struct cfile *cf, off64_t d)
{
  unsigned char dd[8];
  dd[0] = d >> 56;
  dd[1] = d >> 48;
  dd[2] = d >> 40;
  dd[3] = d >> 32;
  dd[4] = d >> 24;
  dd[5] = d >> 16;
  dd[6] = d >> 8;
  dd[7] = d;
  if (cf->write(cf, dd, 8) != 8)
    {
      perror("write64");
      exit(1);
    }
}

static unsigned int read32(struct cfile *bfp)
{
  unsigned char d[4];
  if (bfp->read(bfp, d, 4) != 4)
    {
      perror("read32 error");
      exit(1);
    }
  return d[0] << 24 | d[1] << 16 | d[2] << 8 | d[3]; 
}

static off64_t read64(struct cfile *bfp)
{
  unsigned char d[8];
  if (bfp->read(bfp, d, 8) != 8)
    {
      perror("read64 error");
      exit(1);
    }
  return (off64_t)d[0] << 56 | (off64_t)d[1] << 48 | (off64_t)d[2] << 40 | (off64_t)d[3] << 32 | (off64_t)d[4] << 24 | (off64_t)d[5] << 16 | (off64_t)d[6] << 8 | (off64_t)d[7]; 
}

void
make(char *iso, char *fiso)
{
  int i, j;
  FILE *fp, *ofp;
  struct rpmpay *pays = 0;
  int payn = 0;
  struct cfile *cfp;
  char buf[8192];
  unsigned int l, l2;
  off64_t o, lo;

  if (!strcmp(iso, "-"))
    fp = stdin;
  else if ((fp = fopen64(iso, "r")) == 0)
    {
      perror(iso);
      exit(1);
    }
  payn = rpmoffs(fp, iso, &pays);
  for (i = j = 0; i < payn; i++)
    {
      if (i && pays[i - 1].o == pays[i].o)
	continue;
      if (i != j)
	pays[j] = pays[i];
      j++;
    }
  payn = j;

  if (!strcmp(fiso, "-"))
    ofp = stdout;
  else if ((ofp = fopen64(fiso, "w")) == 0)
    {
      perror(fiso);
      exit(1);
    }
  fputc('F', ofp);
  fputc('I', ofp);
  fputc('S', ofp);
  fputc('O', ofp);
  fputc(0, ofp);
  fputc(0, ofp);
  fputc(0, ofp);
  fputc(1, ofp);
  cfp = cfile_open(CFILE_OPEN_WR, CFILE_IO_FILE, ofp, CFILE_COMP_GZ, CFILE_LEN_UNLIMITED, 0, 0);
  if (!cfp)
    {
      fprintf(stderr, "could not open compression stream\n");
      exit(1);
    }
  write32(cfp, payn);
  for (i = 0; i < payn; i++)
    {
      write64(cfp, pays[i].o);
      write32(cfp, pays[i].l);
      j = strlen(pays[i].name) + 1;
      write32(cfp, j);
      if (cfp->write(cfp, pays[i].name, j) != j)
	{
	  fprintf(stderr, "write error\n");
	  exit(1);
	}
      if (cfp->write(cfp, pays[i].lmd5, 16) != 16)
	{
	  fprintf(stderr, "write error\n");
	  exit(1);
	}
      if (cfp->write(cfp, pays[i].hmd5, 16) != 16)
	{
	  fprintf(stderr, "write error\n");
	  exit(1);
	}
    }
  o = 0;
  if (fseeko64(fp, o, SEEK_SET))
    {
      fprintf(stderr, "%s: seek error\n", iso);
      exit(1);
    }
  for (i = 0; i < payn; i++)
    {
      if (o < pays[i].o)
	{
	  lo = pays[i].o - o;
	  while (lo > 0)
	    {
	      l2 = lo > sizeof(buf) ? sizeof(buf) : lo;
	      if (fread(buf, l2, 1, fp) != 1)
		{
		  fprintf(stderr, "%s: read error\n", iso);
		  exit(1);
		}
	      if (cfp->write(cfp, buf, l2) != l2)
		{
		  fprintf(stderr, "write error\n");
		  exit(1);
		}
	      lo -= l2;
	    }
          o = pays[i].o;
	}
      o += pays[i].l;
      if (fseeko64(fp, o, SEEK_SET))
	{
	  fprintf(stderr, "%s: seek error\n", iso);
	  exit(1);
	}
    }
  /* now to EOF */
  while ((l = fread(buf, 1, sizeof(buf), fp)) > 0)
    {
      if (cfp->write(cfp, buf, l) != l)
	{
	  fprintf(stderr, "write error\n");
	  exit(1);
	}
    }
  if (ferror(fp))
    {
      fprintf(stderr, "%s: read error\n", iso);
      exit(1);
    }
  if (fp != stdin)
    fclose(fp);
  if (cfp->close(cfp) == -1)
    {
      fprintf(stderr, "close error\n");
      exit(1);
    }
  if (fflush(ofp) || (ofp != stdout && fclose(ofp) != 0))
    {
      fprintf(stderr, "write error\n");
      exit(1);
    }
}

static int
readfiso(FILE *fp, char *fiso, struct cfile **cfpp, struct rpmpay **paysp)
{
  char magic[8];
  unsigned int version;
  struct cfile *cfp;
  int i, payn, nl;
  struct rpmpay *pays;
  off64_t o;

  if (fread(magic, 8, 1, fp) != 1)
    {
      fprintf(stderr, "%s: not a fragiso file\n", fiso);
      exit(1);
    }
  if (magic[0] != 'F' || magic[1] != 'I' || magic[2] != 'S' || magic[3] != 'O')
    {
      fprintf(stderr, "%s: not a fragiso file\n", fiso);
      exit(1);
    }
  version = magic[4] << 24 | magic[5] << 16 | magic[6] << 8 || magic[7];
  if (version != 1)
    {
      fprintf(stderr, "%s: unknown fragiso version: %d\n", fiso, version);
      exit(1);
    }
  cfp = cfile_open(CFILE_OPEN_RD, CFILE_IO_FILE, fp, CFILE_COMP_XX, CFILE_LEN_UNLIMITED, 0, 0);
  if (!cfp)
    {
      fprintf(stderr, "could not open compression stream\n");
      exit(1);
    }
  payn = read32(cfp);
  pays = xmalloc2(payn, sizeof(*pays));
  o = 0;
  for (i = 0; i < payn; i++)
    {
      pays[i].o = read64(cfp);
      pays[i].l = read32(cfp);
      if (pays[i].o <= o || pays[i].l < 0x70)
	{
	  fprintf(stderr, "%s: bad fragiso\n", fiso);
	  exit(1);
	}
      o = pays[i].o;
      nl = read32(cfp);
      pays[i].name = xmalloc(nl + 1);
      if (cfp->read(cfp, pays[i].name, nl) != nl)
	{
	  fprintf(stderr, "read error\n");
	  exit(1);
	}
      pays[i].name[nl] = 0;
      if (cfp->read(cfp, pays[i].lmd5, 16) != 16)
	{
	  fprintf(stderr, "read error\n");
	  exit(1);
	}
      if (cfp->read(cfp, pays[i].hmd5, 16) != 16)
	{
	  fprintf(stderr, "read error\n");
	  exit(1);
	}
    }
  *cfpp = cfp;
  *paysp = pays;
  return payn;
}

static char *
checknamearch(char *na)
{
  int i, c, n;
  n = 0;
  for (i = 0; ; i++)
    {
      c = ((unsigned char *)na)[i];
      if (c <= 32 || c == '/')
	break;
      if (c == '.')
	{
	  if (i == 0 || !na[i + 1])
	    break;
	  n++;
	}
    }
  if (c || !n)
    return "unknown.unknown";
  return na;
}

static void
list(struct rpmpay *pays, int payn)
{
  int i, j;
  for (i = 0; i < payn; i++)
    {
      printf("%010llx:%08x ", (unsigned long long)pays[i].o, pays[i].l);
      for (j = 0; j < 16; j++)
	{
	  putchar("0123456789abcdef"[pays[i].lmd5[j] >> 4]);
	  putchar("0123456789abcdef"[pays[i].lmd5[j] & 15]);
	}
      for (j = 0; j < 16; j++)
	{
	  putchar("0123456789abcdef"[pays[i].hmd5[j] >> 4]);
	  putchar("0123456789abcdef"[pays[i].hmd5[j] & 15]);
	}
      printf(" %s\n", checknamearch(pays[i].name));
    }
}

void
listfiso(char *fiso)
{
  FILE *fp;
  struct cfile *cf;
  int payn;
  struct rpmpay *pays;

  if (!strcmp(fiso, "-"))
    fp = stdin;
  else if ((fp = fopen64(fiso, "r")) == 0)
    {
      perror(fiso);
      exit(1);
    }
  payn = readfiso(fp, fiso, &cf, &pays);
  cf->close(cf);
  if (fp != stdin)
    fclose(fp);
  list(pays, payn);
}

void
listiso(char *iso)
{
  FILE *fp;
  int payn, i, j;
  struct rpmpay *pays;

  if (!strcmp(iso, "-"))
    fp = stdin;
  else if ((fp = fopen64(iso, "r")) == 0)
    {
      perror(iso);
      exit(1);
    }
  payn = rpmoffs(fp, iso, &pays);
  if (fp != stdin)
    fclose(fp);
  for (i = j = 0; i < payn; i++)
    {
      if (i && pays[i - 1].o == pays[i].o)
	continue;
      if (i != j)
	pays[j] = pays[i];
      j++;
    }
  payn = j;
  list(pays, payn);
}

void
assemble(char *fiso, char *dir, char *iso)
{
  FILE *fp, *rfp, *ofp;
  struct cfile *cf;
  int i, payn;
  struct rpmpay *pays;
  char *dbuf;
  int dl;
  off64_t o, lo;
  unsigned char buf[8192];
  int l2;
  unsigned int l, cl = 0, cl2;
  MD5_CTX ctx;
  int start;
  unsigned char lmd5[16];

  dl = strlen(dir) + 1;
  dbuf = xmalloc(dl + 10 + 1 + 8 + 1);
  strcpy(dbuf, dir);
  dbuf[dl - 1] = '/';

  if (!strcmp(fiso, "-"))
    fp = stdin;
  else if ((fp = fopen64(fiso, "r")) == 0)
    {
      perror(fiso);
      exit(1);
    }
  payn = readfiso(fp, fiso, &cf, &pays);

  if (!strcmp(iso, "-"))
    ofp = stdout;
  else if ((ofp = fopen64(iso, "w")) == 0)
    {
      perror(iso);
      exit(1);
    }
  o = 0;
  for (i = 0; i < payn; i++)
    {
      if (o < pays[i].o)
	{
	  lo = pays[i].o - o;
	  while (lo > 0)
	    {
	      l2 = lo > sizeof(buf) ? sizeof(buf) : lo;
	      if (cf->read(cf, buf, l2) != l2)
		{
		  fprintf(stderr, "%s: read error\n", fiso);
		  exit(1);
		}
	      if (fwrite(buf, l2, 1, ofp) != 1)
		{
		  fprintf(stderr, "%s: write error\n", iso);
		  exit(1);
		}
              lo -= l2;
	    }
	}
      o = pays[i].o;
      sprintf(dbuf + dl, "%010llx:%08x", (unsigned long long)pays[i].o, pays[i].l);
      if ((rfp = fopen64(dbuf, "r")) == 0)
	{
	  perror(dbuf);
	  exit(1);
	}
      l = pays[i].l;
      rpmMD5Init(&ctx);
      start = 1;
      while (l > 0)
	{
	  l2 = l > sizeof(buf) ? sizeof(buf) : l;
	  if (fread(buf, l2, 1, rfp) != 1)
	    {
	      fprintf(stderr, "%s: read error\n", dbuf);
	      exit(1);
	    }
          if (start)
	    {
	      if (get4n(buf) != 0xedabeedb || get4n(buf + 0x60) != 0x8eade801)
		{
		  fprintf(stderr, "%s: not a rpm\n", dbuf);
		  exit(1);
		}
	      cl = 0x70 + get4n(buf + 0x68) * 16 + get4n(buf + 0x6c);
	      if ((cl & 7) != 0)
		cl += 8 - (cl & 7);
	      if (cl > pays[i].l)
		{
		  fprintf(stderr, "%s: bad rpm\n", dbuf);
		  exit(1);
		}
	      start = 0;
	    }
	  if (cl)
	    {
	      cl2 = cl > l2 ? l2 : cl;
	      rpmMD5Update(&ctx, buf, cl2);
	      cl -= cl2;
	    }
	  if (fwrite(buf, l2, 1, ofp) != 1)
	    {
	      fprintf(stderr, "%s: write error\n", iso);
	      exit(1);
	    }
	  l -= l2;
	}
      fclose(rfp);
      rpmMD5Final(lmd5, &ctx);
      if (memcmp(lmd5, pays[i].lmd5, 16))
	{
	  fprintf(stderr, "%s: rpm does not match\n", dbuf);
	  exit(1);
	}
      o += pays[i].l;
    }
  while ((l2 = cf->read(cf, buf, sizeof(buf))) > 0)
    {
      if (fwrite(buf, l2, 1, ofp) != 1)
	{
	  fprintf(stderr, "%s: write error\n", iso);
	  exit(1);
	}
    }
  if (l2)
    {
      fprintf(stderr, "%s: read error\n", fiso);
      exit(1);
    }
  if (fflush(ofp) || (ofp != stdout && fclose(ofp) != 0))
    {
      fprintf(stderr, "%s: write error\n", iso);
      exit(1);
    }
}

void
fill(char *fiso, char *iso, int mopt)
{
  FILE *fp, *ofp;
  struct cfile *cf;
  int i, payn;
  struct rpmpay *pays;
  off64_t o, lo;
  unsigned char buf[8192];
  unsigned int cl, dl, cl2;
  MD5_CTX ctx, mctx;
  unsigned char lmd5[16];
  int mfd;
  int l2;

  if (!strcmp(fiso, "-"))
    fp = stdin;
  else if ((fp = fopen64(fiso, "r")) == 0)
    {
      perror(fiso);
      exit(1);
    }
  payn = readfiso(fp, fiso, &cf, &pays);
  mfd = 1;
  if (!strcmp(iso, "-"))
    {
      ofp = stdout;
      mfd = 2;
    }
  else if ((ofp = fopen64(iso, "r+")) == 0)
    {
      perror(iso);
      exit(1);
    }
  rpmMD5Init(&mctx);
  o = 0;
  for (i = 0; i < payn; i++)
    {
      if (o < pays[i].o)
	{
	  fseeko64(ofp, o, SEEK_SET);
	  lo = pays[i].o - o;
	  while (lo > 0)
	    {
	      l2 = lo > sizeof(buf) ? sizeof(buf) : lo;
	      if (cf->read(cf, buf, l2) != l2)
		{
		  fprintf(stderr, "%s: read error\n", fiso);
		  exit(1);
		}
	      if (fwrite(buf, l2, 1, ofp) != 1)
		{
		  fprintf(stderr, "%s: write error\n", iso);
		  exit(1);
		}
	      if (mopt)
	        rpmMD5Update(&mctx, buf, l2);
              lo -= l2;
	    }
	}
      o = pays[i].o;
      /* verify that right rpm is at pos o */
      fseeko64(ofp, o, SEEK_SET);
      if (fread(buf, 0x70, 1, ofp) != 1)
	{
	  fprintf(stderr, "%s: read error\n", iso);
	  exit(1);
	}
      if (mopt)
	rpmMD5Update(&mctx, buf, 0x70);
      if (get4n(buf) != 0xedabeedb || get4n(buf + 0x60) != 0x8eade801)
	{
	  fprintf(stderr, "%llx: not a rpm\n", (unsigned long long)o);
	  exit(1);
	}
      cl = 0x70 + get4n(buf + 0x68) * 16 + get4n(buf + 0x6c);
      if ((cl & 7) != 0)
	cl += 8 - (cl & 7);
      if (cl > pays[i].l)
	{
	  fprintf(stderr, "%llx: bad rpm\n", (unsigned long long)o);
	  exit(1);
	}
      dl = pays[i].l - cl;
      rpmMD5Init(&ctx);
      rpmMD5Update(&ctx, buf, 0x70);
      cl -= 0x70;
      while (cl)
	{
	  cl2 = cl > sizeof(buf) ? sizeof(buf) : cl;
	  if (fread(buf, cl2, 1, ofp) != 1)
	    {
	      fprintf(stderr, "%s: read error\n", iso);
	      exit(1);
	    }
	  rpmMD5Update(&ctx, buf, cl2);
	  if (mopt)
	    rpmMD5Update(&mctx, buf, cl2);
	  cl -= cl2;
	}
      rpmMD5Final(lmd5, &ctx);
      if (memcmp(lmd5, pays[i].lmd5, 16))
	{
	  fprintf(stderr, "%llx: rpm lead+signature does not match\n", (unsigned long long)o);
	  exit(1);
	}
      rpmMD5Init(&ctx);
      while (dl)
	{
	  cl2 = dl > sizeof(buf) ? sizeof(buf) : dl;
	  if (fread(buf, cl2, 1, ofp) != 1)
	    {
	      fprintf(stderr, "%s: read error\n", iso);
	      exit(1);
	    }
	  rpmMD5Update(&ctx, buf, cl2);
	  if (mopt)
	    rpmMD5Update(&mctx, buf, cl2);
	  dl -= cl2;
	}
      rpmMD5Final(lmd5, &ctx);
      if (memcmp(lmd5, pays[i].hmd5, 16))
	{
	  fprintf(stderr, "%llx: rpm header+payload does not match\n", (unsigned long long)o);
	  exit(1);
	}
      o += pays[i].l;
    }
  fseeko64(ofp, o, SEEK_SET);
  while ((l2 = cf->read(cf, buf, sizeof(buf))) > 0)
    {
      if (fwrite(buf, l2, 1, ofp) != 1)
	{
	  fprintf(stderr, "%s: write error\n", iso);
	  exit(1);
	}
      if (mopt)
	rpmMD5Update(&mctx, buf, l2);
      o += l2;
    }
  if (l2)
    {
      fprintf(stderr, "%s: read error\n", fiso);
      exit(1);
    }
  if (fflush(ofp))
    {
      fprintf(stderr, "%s: write error\n", iso);
      exit(1);
    }
  if (ftruncate64(fileno(ofp), o))
    {
      fprintf(stderr, "%s: truncate error\n", iso);
      exit(1);
    }
  if (ofp != stdout && fclose(ofp) != 0)
    {
      fprintf(stderr, "%s: write error\n", iso);
      exit(1);
    }
  if (mopt)
    {
      rpmMD5Final(lmd5, &mctx);
      for (i = 0; i < 16; i++)
	{
	  buf[2 * i + 0] = "0123456789abcdef"[lmd5[i] >> 4];
	  buf[2 * i + 1] = "0123456789abcdef"[lmd5[i] & 15];
	}
      buf[32] = '\n';
      write(mfd, buf, 33);
    }
}

void
extract(char *iso, char *offlen, char *rpm)
{
  off64_t o;
  unsigned int l, l2;
  FILE *fp, *ofp;
  int i;
  char buf[8192];

  if (strlen(offlen) !=  10 + 1 + 8 || offlen[10] != ':')
    {
      fprintf(stderr, "bad off:len %s\n", offlen);
      exit(1);
    }
  o = 0;
  for (i = 0; i < 10; i++)
    {
      o <<= 4;
      if (offlen[i] >= '0' && offlen[i] <= '9')
	o |= offlen[i] - '0';
      else if (offlen[i] >= 'a' && offlen[i] <= 'f')
	o |= offlen[i] - ('a' - 10);
      else if (offlen[i] >= 'A' && offlen[i] <= 'F')
	o |= offlen[i] - ('A' - 10);
      else
	{
	  fprintf(stderr, "bad off:len %s\n", offlen);
	  exit(1);
	}
    }
  l = 0;
  for (i = 0; i < 8; i++)
    {
      l <<= 4;
      if (offlen[11 + i] >= '0' && offlen[11 + i] <= '9')
	l |= offlen[11 + i] - '0';
      else if (offlen[11 + i] >= 'a' && offlen[11 + i] <= 'f')
	l |= offlen[11 + i] - ('a' - 10);
      else if (offlen[11 + i] >= 'A' && offlen[11 + i] <= 'F')
	l |= offlen[11 + i] - ('A' - 10);
      else
	{
	  fprintf(stderr, "bad off:len %s\n", offlen);
	  exit(1);
	}
    }
  if (!strcmp(iso, "-"))
    fp = stdin;
  else if ((fp = fopen64(iso, "r")) == 0)
    {
      perror(iso);
      exit(1);
    }
  if (fseeko64(fp, o, SEEK_SET) != 0)
    {
      perror("fseek");
      exit(1);
    }
  if (!strcmp(rpm, "-"))
    ofp = stdout;
  else if ((ofp = fopen64(rpm, "w")) == 0)
    {
      perror(rpm);
      exit(1);
    }
  while (l > 0)
    {
      l2 = l > sizeof(buf) ? sizeof(buf) : l;
      if (fread(buf, l2, 1, fp) != 1)
	{
	  fprintf(stderr, "%s: read error\n", iso);
	  exit(1);
	}
      if (fwrite(buf, l2, 1, ofp) != 1)
	{
	  fprintf(stderr, "%s: write error\n", rpm);
	  exit(1);
	}
      l -= l2;
    }
  if (fflush(ofp) || (ofp != stdout && fclose(ofp) != 0))
    {
      fprintf(stderr, "write error\n");
      exit(1);
    }
}

int
main(int argc, char **argv)
{
  if (argc == 4 && !strcmp(argv[1], "make"))
    make(argv[2], argv[3]);
  else if (argc == 3 && !strcmp(argv[1], "list"))
    listfiso(argv[2]);
  else if (argc == 3 && !strcmp(argv[1], "listiso"))
    listiso(argv[2]);
  else if (argc == 5 && !strcmp(argv[1], "assemble"))
    assemble(argv[2], argv[3], argv[4]);
  else if (argc == 5 && !strcmp(argv[1], "fill") && !strcmp(argv[2], "-m"))
    fill(argv[3], argv[4], 1);
  else if (argc == 4 && !strcmp(argv[1], "fill"))
    fill(argv[2], argv[3], 0);
  else if (argc == 5 && !strcmp(argv[1], "extract"))
    extract(argv[2], argv[3], argv[4]);
  else
    {
      fprintf(stderr, "usage: fragiso make <iso> <fiso>\n");
      fprintf(stderr, "       fragiso list <fiso>\n");
      fprintf(stderr, "       fragiso listiso <iso>\n");
      fprintf(stderr, "       fragiso assemble <fiso> <dir> <iso>\n");
      fprintf(stderr, "       fragiso fill [-m] <fiso> <iso>\n");
      fprintf(stderr, "       fragiso extract <iso> <off/len> <rpm>\n");
      exit(1);
    }
  exit(0);
}
