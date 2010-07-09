/*
 * Copyright (c) 2004 Michael Schroeder (mls@suse.de)
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
#include <sys/stat.h>

#include <bzlib.h>
#include <zlib.h>
#include <lzma.h>

#include "util.h"
#include "md5.h"
#include "rpmhead.h"
#include "rpml.h"
#include "cpio.h"
#include "delta.h"
#include "cfile.h"
#include "deltarpm.h"

char *
headtofiles(struct rpmhead *h, struct rpmlfile **filesp, int *nfilesp)
{
  char *nevr, *n;
  int cnt, i;
  struct rpmlfile *files;
  unsigned int *fileflags, *filemodes;
  char **filelist, **filemd5s;

  nevr = headtonevr(h);
  if (!nevr)
    return 0;
  filelist = headexpandfilelist(h, &cnt);
  if (!filelist || !cnt)
    {
      *nfilesp = 0;
      *filesp = 0;
      return nevr;
    }
  fileflags = headint32(h, TAG_FILEFLAGS, (int *)0);
  filemd5s = headstringarray(h, TAG_FILEMD5S, (int *)0);
  filemodes = headint16(h, TAG_FILEMODES, (int *)0);
  files = xmalloc2(cnt, sizeof(*files));
  for (i = 0; i < cnt; i++)
    {
      n = filelist[i];
      if (*n == '/')
	n++;
      files[i].name = xmalloc(strlen(n) + 1);
      strcpy(files[i].name, n);
      files[i].mode = filemodes[i];
      files[i].fflags = fileflags[i];
      parsemd5(filemd5s[i], files[i].md5);
    }
  *filesp = files;
  *nfilesp = cnt;
  free(fileflags);
  free(filemd5s);
  free(filemodes);
  free(filelist);
  return nevr;
}

unsigned char *seq;
int seqp;
int seql;

int lastseq = -1;
int lastseqstart = 0;

void
addtoseqn(int n)
{
  int l = 1, j = 8;
  while (n >= j)
    {
      j *= 8;
      l++;
    }
  if (seqp + l > seql * 2)
    {
      seq = xrealloc(seq, seql + 32);
      seql += 32;
    }
  while (l-- > 0)
    {
      if (seqp & 1)
	seq[seqp / 2] |= (n & 7) | (l ? 8 : 0);
      else
	seq[seqp / 2] = ((n & 7) | (l ? 8 : 0)) << 4;
      seqp++;
      n >>= 3;
    }
}

void
addtoseq(int i)
{
  int n;
  // fprintf(stderr, "addtoseq %d lastseqstart=%d lastseq=%d\n", i, lastseqstart, lastseq);
  if (i == lastseq + 1)
    {
      lastseq = i;
      return;
    }
  n = lastseq - lastseqstart + 1;
  if (n)
    addtoseqn(n);
  if (i > lastseq + 1 && lastseq >= 0)
    {
      addtoseqn(i - lastseq - 1);
    }
  else if (i != -1)
    {
      addtoseqn(0);
      addtoseqn(i);
    }
  lastseq = lastseqstart = i;
}

struct prune {
  char *name;
};

struct prune *prunes;
int prunen;

void
read_prunelist(char *file)
{
  FILE *fp;
  char *buf, *bp;
  int i, c, bufl;
  struct prune *p;

  if ((fp = fopen(file, "r")) == 0)
    {
      perror(file);
      exit(1);
    }
  bufl = 256;
  buf = xmalloc(256);
  prunes = xmalloc(sizeof(*prunes) * 16);
  for (i = 0;;)
    {
      c = getc(fp);
      if (c && c != EOF && c != '\n')
	{
	  buf[i++] = c;
          if (i == bufl)
	    {
	      bufl += 256;
	      buf = xrealloc(buf, bufl);
	    }
	  continue;
	}
      buf[i] = 0;
      bp = buf;
      if (*bp == '/')
	bp++;
      else if (*bp == '.' && bp[1] == '/')
	bp += 2;
      if (!*bp && c == EOF)
	break;
      if (!*bp)
	continue;
      if ((prunen & 15) == 0)
	prunes = xrealloc2(prunes, prunen + 16, sizeof(*prunes));
      p = prunes + prunen++;
      p->name = xmalloc(i + 1 - (bp - buf));
      memcpy(p->name, bp, i + 1 - (bp - buf));
      i = 0;
    }
  fclose(fp);
}

int
is_pruned(char *n)
{
  int i;
  struct prune *p = prunes;

  for (i = 0; i < prunen; i++, p++)
    if (!strcmp(p->name, n))
      return 1;
  return 0;
}


int
is_unpatched(char *n, struct rpmlfile *files1, int nfiles1, struct rpmlfile *files2, int nfiles2, char *md5s)
{
  int i;
  unsigned char md5[16];

  for (i = 0; i < nfiles2; i++)
    if (!strcmp(n, files2[i].name))
      break;
  if (i == nfiles2)
    return 0;
  if (!(files2[i].fflags & FILE_UNPATCHED))
    return 0;
  for (i = 0; i < nfiles1; i++)
    if (!strcmp(n, files1[i].name))
      break;
  if (i == nfiles1)
    return 1;		/* should not happen... */
  parsemd5(md5s, md5);
  if (memcmp(md5, files1[i].md5, 16))
    return 1;		/* file content may be different */
  return 0;
}

struct streamdata {
  bsuint bsize;

  unsigned char *old;
  bsuint oldl;
  bsuint oldskip;
  int oldeof;

  unsigned char *new;
  bsuint newl;
  bsuint newskip;
  int neweof;

  struct cfile *newf;
  unsigned char *xnewdata;
  bsuint xnewdatal;

  void *stepd;
  bsuint scan;
  bsuint lastpos;
  bsuint lastscan;

  struct cfile *cfa;	/* add block */
  struct cfile *cfi;	/* in data */

  struct instr *instr;
  int instrlen;
};

struct streamdata sd;	/* hack: global for now */

void
addtocpio_stream(unsigned char *d, int l)
{
  bsuint bsize = sd.bsize;
  if (sd.lastscan == sd.newl && sd.neweof)
    {
      sd.oldskip += sd.oldl + l;
      sd.oldl = 0;
      return;
    }
  for (;;)
    {
      if (sd.oldl < bsize && !sd.oldeof)
	{
	  int l2 = bsize - sd.oldl;
	  if (l2 > l)
	    l2 = l;
	  memcpy(sd.old + sd.oldl, d, l2);
	  sd.oldl += l2;
          l -= l2;
	  d += l2;
	  if (sd.oldl < bsize)
	    return;
	}
      while (sd.newl < bsize && !sd.neweof)
	{
	  int l2 = bsize - sd.newl;
	  if (sd.xnewdatal)
	    {
	      if (l2 > sd.xnewdatal)
		l2 = sd.xnewdatal;
	      memcpy(sd.new + sd.newl, sd.xnewdata, l2);
	      sd.newl += l2;
	      sd.xnewdata += l2;
	      sd.xnewdatal -= l2;
	      continue;
	    }
	  l2 = sd.newf->read(sd.newf, sd.new + sd.newl, l2);
	  if (l2 < 0)
	    {
	      fprintf(stderr, "payload read failed\n");
	      exit(1);
	    }
	  if (l2 == 0)
	    sd.neweof = 1;
	  sd.newl += l2;
	}
      if (sd.lastscan != sd.newl)
	{
	  struct instr instr;
	  mkdiff_step(sd.stepd, sd.old, sd.oldl, sd.new, sd.newl, &instr, &sd.scan, &sd.lastpos, &sd.lastscan);
	  if (instr.copyout && !sd.oldeof && (sd.lastscan == sd.newl || instr.copyoutoff + instr.copyout == sd.oldl))
	    {
	      /* incomplete match, ignore indata part */
	      instr.copyin = 0;
	      sd.scan = sd.lastscan = instr.copyinoff;
	      sd.lastpos = instr.copyoutoff + instr.copyout;
	    }
	  else if (!instr.copyout && sd.lastscan == sd.newl)
	    {
	      /* no match found in old data, advance if we're behind */
	      if (sd.lastpos + sd.oldskip < sd.lastscan + sd.newskip)
	        sd.lastpos = sd.oldl;
	    }
	  /* printf("INSTR: %d@%d %d@%d\n", instr.copyout, instr.copyoutoff + sd.oldskip, instr.copyin, instr.copyinoff + sd.newskip); */
	  if (instr.copyin)
	    {
	      if (instr.copyinoff + instr.copyin > sd.newl)
		abort();
	      if (sd.cfi->write(sd.cfi, sd.new + instr.copyinoff, instr.copyin) != instr.copyin)
		{
		  fprintf(stderr, "could not create indata block\n");
		  exit(1);
		}
	    }
	  if (instr.copyout && sd.cfa)
	    {
	      bsuint lenf = instr.copyout;
	      bsuint lastpos = instr.copyoutoff;
	      bsuint lastscan = instr.copyinoff - lenf;
	      if (instr.copyoutoff + instr.copyout > sd.oldl)
		abort();
	      if (instr.copyinoff - lenf + instr.copyout > sd.newl)
		abort();
	      while (lenf > 0) 
		{
		  unsigned char addblk[4096];
		  int len2, i;

		  len2 = lenf > 4096 ? 4096 : lenf;
		  for (i = 0; i < len2; i++) 
		    addblk[i] = sd.new[lastscan + i] - sd.old[lastpos + i];
		  if (sd.cfa->write(sd.cfa, addblk, len2) != len2)
		    {
		      fprintf(stderr, "could not create compressed add block\n");
		      exit(1);
		    }
		  lastscan += len2;
		  lastpos += len2;
		  lenf -= len2;
		}
	    }
	  instr.copyinoff += sd.newskip;
	  instr.copyoutoff += sd.oldskip;
	  if (sd.instrlen && sd.instr[sd.instrlen - 1].copyin == 0 && sd.instr[sd.instrlen - 1].copyoutoff + sd.instr[sd.instrlen - 1].copyout == instr.copyoutoff)
	    {
	      /* just add to last instruction */
	      sd.instr[sd.instrlen - 1].copyin = instr.copyin;
	      sd.instr[sd.instrlen - 1].copyinoff = instr.copyinoff;
	      sd.instr[sd.instrlen - 1].copyout += instr.copyout;
	    }
	  else if (instr.copyin || instr.copyout)
	    {
	      if ((sd.instrlen & 31) == 0)
		{
		  if (sd.instr)
		    sd.instr = realloc(sd.instr, sizeof(*sd.instr) * (sd.instrlen + 32));
		  else
		    sd.instr = malloc(sizeof(*sd.instr) * (sd.instrlen + 32));
		  if (!sd.instr)
		    {
		      fprintf(stderr, "out of memory\n");
		      exit(1);
		    }
		}
	      sd.instr[sd.instrlen] = instr;
	      sd.instrlen++;
	    }
	}
      if (sd.lastscan > bsize / 4 && !sd.neweof)
	{
	  if (sd.newl > sd.lastscan)
	    memmove(sd.new, sd.new + sd.lastscan, sd.newl - sd.lastscan);
	  sd.newl -= sd.lastscan;
	  sd.newskip += sd.lastscan;
	  sd.scan -= sd.lastscan;
	  sd.lastscan = 0;
	}
      if (sd.lastpos > bsize / 2 && !sd.oldeof)
	{
	  bsuint move = sd.lastpos - bsize / 4;
	  if (sd.lastpos + sd.oldskip + bsize < sd.lastscan + sd.newskip)
	    move = sd.lastpos;
	  if (move > sd.lastpos)
	    move = sd.lastpos;
	  if (sd.oldl > move)
	    memmove(sd.old, sd.old + move, sd.oldl - move);
	  sd.oldl -= move;
	  sd.oldskip += move;
	  sd.lastpos -= move;
	  mkdiff_step_freedata(sd.stepd);
	}
      if (sd.lastscan == sd.newl && sd.neweof)
	{
	  sd.oldskip += sd.oldl + l;
	  sd.oldl = 0;
	  mkdiff_step_freedata(sd.stepd);
	  return;
	}
    }
}

void
addtocpio(unsigned char **cpiop, bsuint *cpiol, unsigned char *d, int l)
{
  bsuint cpl = *cpiol;
  if (*cpiop == (unsigned char *)&sd)
    {
      *cpiol += l;
      addtocpio_stream(d, l);
      return;
    }
  if (cpl + l < cpl || cpl + l + 65535 < cpl + l)
    {
      fprintf(stderr, "cpio archive to big\n");
      exit(1);
    }
  if (cpl == 0 || ((cpl - 1) & 65535) + l >= 65536)
    *cpiop = xrealloc(*cpiop, (cpl + l + 65535) & ~65535);
  memcpy(*cpiop + cpl, d, l);
  *cpiol = cpl + l;
}

void
convertinstr(struct instr *instr, int instrlen, struct deltarpm *d)
{
  int i, j;
  bsuint x1, x2, x3, off;
  unsigned int *b1;
  int nb1;
  unsigned int *b2;
  int nb2;

  b1 = b2 = 0;
  nb1 = nb2 = 0;
  j = 0;
  off = 0;
  for (i = 0; i < instrlen; i++)
    {
      x1 = instr[i].copyout;
      x2 = instr[i].copyin;
      x3 = instr[i].copyoutoff;
      if (!x1 && !x2)
	continue;
      if (x1)
        {
retry1:
	  if ((nb2 & 15) == 0)
	    b2 = xrealloc2(b2, nb2 + 16, 2 * sizeof(unsigned int));
	  if (x3 > off && x3 - off >= 0x80000000)
	    {
	      b2[2 * nb2] = 0x7fffffff;
	      b2[2 * nb2 + 1] = 0;
	      nb2++;
	      off += 0x7fffffff;
	      j++;
	      goto retry1;
	    }
	  if (x3 < off && off - x3 >= 0x80000000)
	    {
	      b2[2 * nb2] = -0x7fffffff;
	      b2[2 * nb2 + 1] = 0;
	      nb2++;
	      off -= 0x7fffffff;
	      j++;
	      goto retry1;
	    }
          b2[2 * nb2] = (int)(x3 - off);
	  if (x1 >= 0x80000000)
	    {
	      b2[2 * nb2 + 1] = 0x7fffffff;
	      nb2++;
	      x1 -= 0x7fffffff;
	      off = x3 = x3 + 0x7fffffff;
	      j++;
	      goto retry1;
	    }
          b2[2 * nb2 + 1] = x1;
          nb2++;
          off = x3 + x1;
          j++;
        }
      if (x2)
        {
retry2:
          if ((nb1 & 15) == 0)
            b1 = xrealloc2(b1, nb1 + 16, 2 * sizeof(unsigned int));
          b1[2 * nb1] = j;
          j = 0;
	  if (x2 >= 0x80000000)
	    {
	      b1[2 * nb1 + 1] = 0x7fffffff;
	      x2 -= 0x7fffffff;
	      nb1++;
	      goto retry2;
	    }
          b1[2 * nb1 + 1] = x2;
          nb1++;
        }
    }
  if (j)
    {
      if ((nb1 & 15) == 0)
        b1 = xrealloc2(b1, nb1 + 16, 2 * sizeof(unsigned int));
      b1[2 * nb1] = j;
      b1[2 * nb1 + 1] = 0;
      nb1++;
    }
  d->inn = nb1;
  d->in = b1;
  d->outn = nb2;
  d->out = b2;
}

unsigned char **
createindatalist(struct instr *instr, int instrlen, struct deltarpm *d, unsigned char *new)
{
  int i, j;
  bsuint off, left, todo;
  unsigned char **indatalist;
  
  left = off = 0;
  j = 0;
  d->inlen = 0;
  indatalist = xcalloc(d->inn, sizeof(unsigned char *));
  for (i = 0; i < d->inn; i++)
    {
      todo = d->in[2 * i + 1];
      while (!left && todo)
	{
	  off = instr[j].copyinoff;
	  left = instr[j].copyin;
	  j++;
	}
      indatalist[i] = new + off;
      off += todo;
      left -= todo;
      d->inlen += todo;
    }
  return indatalist;
}

int
str2comp(char *comp)
{
  int n = strlen(comp);
  if (n > 2 && n < 20 && comp[n - 2] == '.' && comp[n - 1] >= '0' && comp[n - 1] <= '9')
    {
      char buf[20];
      strcpy(buf, comp);
      buf[n - 2] = 0;
      return cfile_setlevel(str2comp(buf), comp[n - 1] - '0');
    }
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
  if (!strcmp(comp, "xz"))
    return CFILE_COMP_XZ;
  if (!strcmp(comp, "uncompressed"))
    return CFILE_COMP_UN;
  fprintf(stderr, "unknown compression type: %s\n", comp);
  exit(1);
}

void
createaddblock(struct instr *instr, int instrlen, struct deltarpm *d, unsigned char *old, unsigned char *new, int comp)
{
  struct cfile *cfa;
  unsigned int l, l2;
  unsigned char blk[4096];
  unsigned char *o;
  int i, j;

  cfa = cfile_open(CFILE_OPEN_WR, CFILE_IO_ALLOC, &d->addblk, comp, CFILE_LEN_UNLIMITED, 0, 0);
  if (!cfa)
    {
      fprintf(stderr, "could not create compressed add block\n");
      exit(1);
    }
  for (i = 0; i < instrlen; i++)
    {
      l = instr[i].copyout;
      o = old + instr[i].copyoutoff;
      while (l)
	{
	  l2 = l > sizeof(blk) ? sizeof(blk) : l;
	  for (j = 0; j < l2; j++)
	    blk[j] = new[j] - o[j];
          if (cfa->write(cfa, blk, l2) != l2)
	    {
	      fprintf(stderr, "could not create compressed add block\n");
	      exit(1);
	    }
	  new += l2;
	  o += l2;
	  l -= l2;
	}
      new += instr[i].copyin;
    }
  d->addblklen = cfa->close(cfa);
}

void
write_seqfile(struct deltarpm *d, char *seqfile)
{
  FILE *ifp;
  int i;

  if ((ifp = fopen(seqfile, "w")) == 0)
    {
      perror(seqfile);
      exit(1);
    }
  fprintf(ifp, "%s-", d->nevr);
  for (i = 0; i < d->seql; i++)
    fprintf(ifp, "%02x", d->seq[i]);
  fprintf(ifp, "\n");
  if (fclose(ifp))
    {
      perror("fclose seqfile");
      exit(1);
    }
}

static int
in_multilib_dir(char *fn)
{
  char *dirs[] = { "lib/", "lib64/", "lib32/", NULL };
  int i;

  for (i = 0; dirs[i] != NULL; i++)
    if (strstr(fn, dirs[i]) != NULL)
      return 1;
  return 0;
}

int
main(int argc, char **argv)
{
  char *rpmname;
  unsigned char rpmlead[96];
  struct rpmhead *h, *sigh;
  char *nevr;
  int filecnt;
  char **filenames, **filemd5s, **filelinktos;
  unsigned int *fileflags, *filemodes, *filerdevs, *filesizes, *fileverify, *filecolors;
  int digestalgo = 1;
  unsigned int *digestalgoarray;
  int i, l, l2, l3;
  int fd, nfd;
  struct cfile *bfd;
  struct cpiophys cph;
  char *namebuf;
  int namebufl;
  char *np;
  char buf[4096];
  int c, skip;
  char *prunelist = 0;
  int cpiocnt = 0;
  int skipped_notfound = 0;
  int skipped_pruned = 0;
  int skipped_unpatched = 0;
  int skipped_badsize = 0;
  int skipped_fileflags = 0;
  int skipped_verifyflags = 0;
  int skipped_multilib = 0;
  int skipped_all = 0;
  int pinfo = 0;
  struct rpmlfile *files1 = 0;
  int nfiles1 = 0;
  char *nevr1 = 0;
  struct rpmlfile *files2 = 0;
  int nfiles2 = 0;
  char *nevr2 = 0;
  struct rpmhead *h2 = 0;
  char *seqfile = 0;
  MD5_CTX seqmd5;
  unsigned char seqmd5res[16];

  unsigned char *oldcpio = 0;
  bsuint oldcpiolen = 0;
  unsigned char *newcpio = 0;
  bsuint newcpiolen = 0;

  bsuint cpiopos, oldadjust;
  unsigned int *offadjs = 0;
  unsigned int offadjn = 0;

  char *payformat;
  MD5_CTX fullmd5;
  unsigned char fullmd5res[16];
  unsigned int fullsize = 0;

  struct cfile *newbz;

  struct instr *instr = 0;
  int instrlen = 0;

  int verbose = 0;
  int version = 3;
  struct deltarpm d;
  unsigned char **indatalist = 0;
  int rpmonly = 0;
  int alone = 0;
  FILE *vfp = 0;

  char *compopt = 0;
  int paycomp = CFILE_COMP_XX;
  int addblkcomp = CFILE_COMP_BZ;
  int targetcomp = CFILE_COMP_XX;
  char *payloadflags;

  bsuint stream = 0;

  memset(&d, 0, sizeof(d));
  memset(&sd, 0, sizeof(sd));
  while ((c = getopt(argc, argv, "vV:prl:s:z:um:")) != -1)
    {
      switch (c)
	{
	case 'l':
	  prunelist = optarg;
	  break;
	case 'u':
	  alone = 1;
	  break;
	case 's':
	  seqfile = optarg;
	  break;
	case 'v':
	  verbose++;
	  break;
	case 'V':
	  version = atoi(optarg);
	  break;
	case 'p':
	  pinfo = 1;
	  break;
	case 'r':
	  rpmonly = 1;
	  break;
	case 'z':
	  compopt = optarg;
	  break;
	case 'm':
	  stream = atoi(optarg) * (1024 * 256);
	  break;
	default:
	  fprintf(stderr, "usage: makedeltarpm [-l <file>] [-s seq] oldrpm newrpm deltarpm\n");
	  exit(1);
	}
    }
  if (verbose)
    vfp = !strcmp("-", argv[argc - 1]) ? stderr : stdout;
  if (compopt)
    {
      char *c2 = strchr(compopt, ',');
      if (c2)
	*c2++ = 0;
      if (*compopt && strcmp(compopt, "rpm") != 0)
        paycomp = str2comp(compopt);
      if (c2)
	{
	  if (!strcmp(c2, "off") != 0)
	    addblkcomp = -1;
	  else
	    addblkcomp = str2comp(c2);
	}
    }
  if (prunelist)
    read_prunelist(prunelist);

  if (argc - optind != (pinfo ? 5 : 3) - alone)
    {
      fprintf(stderr, "usage: makedeltarpm [-l <file>] [-s seq] oldrpm newrpm deltarpm\n");
      exit(1);
    }
  if (version != 1 && version != 2 && version != 3)
    {
      fprintf(stderr, "illegal version: %d\n", version);
      exit(1);
    }
  if (pinfo)
    {
      FILE *pfp;
      int pfd;

      pfp = fopen(argv[argc - 5 + alone], "r");
      if (!pfp)
	{
	  perror(argv[argc - 5 + alone]);
	  exit(1);
	}
      nevr1 = rpmlread(pfp, argv[argc - 5 + alone], 0, &files1, &nfiles1);
      fclose(pfp);
      pfd = open(argv[argc - 4 + alone], O_RDONLY);
      if (pfd < 0)
	{
	  perror(argv[argc - 4 + alone]);
	  exit(1);
	}
      if (read(pfd, rpmlead, 4) != 4)
	{
	  fprintf(stderr, "%s: not a rpm or rpmlist\n", argv[argc - 4 + alone]);
	  exit(1);
	}
      if (rpmlead[0] != 0xed || rpmlead[1] != 0xab || rpmlead[2] != 0xee || rpmlead[3] != 0xdb)
	{
	  pfp = fdopen(pfd, "r");
	  if (!pfp)
	    {
	      perror(argv[argc - 4 + alone]);
	      exit(1);
	    }
	  nevr2 = rpmlread(pfp, argv[argc - 4 + alone], 1, &files2, &nfiles2);
	  fclose(pfp);
	}
      else
	{
	  if (read(pfd, rpmlead + 4, 92) != 92 || rpmlead[4] != 0x03 || rpmlead[0x4e] != 0 || rpmlead[0x4f] != 5)
	    {
	      fprintf(stderr, "%s: not a v3 rpm or not new header styles\n", argv[argc - 4 + alone]);
	      exit(1);
	    }
	  h2 = readhead(pfd, 1);
	  if (!h2)
	    {
	      fprintf(stderr, "could not read signature header\n");
	      exit(1);
	    }
	  free(h2);
	  h2 = readhead(pfd, 0);
	  if (!h2)
	    {
	      fprintf(stderr, "could not read header\n");
	      exit(1);
	    }
	  close(pfd);
	  nevr2 = headtofiles(h2, &files2, &nfiles2);
	}
    }

  rpmMD5Init(&seqmd5);

  /* open old rpm */
  /* (if alone == 1,  oldrpm == newrpm) */
  rpmname = argv[argc - 3 + alone];
  if (!strcmp(rpmname, "-"))
    fd = 0;
  else if ((fd = open(rpmname, O_RDONLY)) < 0)
    {
      perror(rpmname);
      exit(1);
    }
  if (read(fd, rpmlead, 96) != 96 || rpmlead[0] != 0xed || rpmlead[1] != 0xab || rpmlead[2] != 0xee || rpmlead[3] != 0xdb)
    {
      fprintf(stderr, "%s: not a rpm\n", rpmname);
      exit(1);
    }
  if (rpmlead[4] != 0x03 || rpmlead[0x4e] != 0 || rpmlead[0x4f] != 5)
    {
      fprintf(stderr, "%s: not a v3 rpm or not new header styles\n", rpmname);
      exit(1);
    }
  sigh = readhead(fd, 1);
  if (!sigh)
    {
      fprintf(stderr, "could not read signature header\n");
      exit(1);
    }
  h = readhead(fd, 0);
  if (!h)
    {
      fprintf(stderr, "could not read header\n");
      exit(1);
    }
  nevr = headtonevr(h);

  if (alone && rpmonly)
    {
      /* this mode just updates the lead and signatures, no need to do a real diff */
      if (verbose)
	fprintf(vfp, "reading rpm header...\n");
      rpmMD5Init(&fullmd5);
      /* don't have to compare, write a "no diff" deltarpm */
      d.h = 0;
      d.name = argv[argc - 1];
      d.version = 0x444c5430 + version;
      memcpy(d.rpmlead, rpmlead, 96);
      d.leadl = 96 + 16 + sigh->cnt * 16 + sigh->dcnt;
      d.lead = xmalloc(d.leadl);
      memcpy(d.lead, rpmlead, 96);
      memcpy(d.lead + 96, sigh->intro, 16);
      memcpy(d.lead + 96 + 16, sigh->data, d.leadl - 96 - 16);
      d.inn = d.outn = 0;
      d.in = d.out = 0;
      d.nevr = nevr;
      d.seql = 16;
      d.seq = xmalloc(d.seql);
      /* calculate seqmd5 and targetmd5 */
      rpmMD5Update(&fullmd5, d.lead , d.leadl);
      rpmMD5Update(&fullmd5, h->intro , 16);
      rpmMD5Update(&fullmd5, h->data, 16 * h->cnt + h->dcnt);
      rpmMD5Update(&seqmd5, h->intro , 16);
      rpmMD5Update(&seqmd5, h->data, 16 * h->cnt + h->dcnt);
      fullsize = d.leadl + 16 + 16 * h->cnt + h->dcnt;
      while ((l = read(fd, buf, sizeof(buf))) > 0)
	{
	  rpmMD5Update(&fullmd5, (unsigned char *)buf, l);
	  rpmMD5Update(&seqmd5, (unsigned char *)buf, l);
	  fullsize += l;
	}
      if (l == -1)
	{
	  fprintf(stderr, "read error\n");
	  exit(1);
	}
      rpmMD5Final(d.seq, &seqmd5);
      rpmMD5Final(d.targetmd5, &fullmd5);
      targetcomp = CFILE_COMP_UN;
      if (paycomp == CFILE_COMP_XX)
	paycomp = CFILE_COMP_GZ;	/* no need for better compression */
      if (addblkcomp == CFILE_COMP_XX)
	addblkcomp = CFILE_COMP_GZ;
      d.targetsize = fullsize;
      d.targetcomp = targetcomp;
      d.targetcomppara = 0;
      d.targetcompparalen = 0;
      d.targetnevr = headtonevr(h);
      d.compheadlen = 16 + 16 * h->cnt + h->dcnt;
      d.offadjn = 0;
      d.offadjs = 0;
      d.payformatoff = 0;
      d.outlen = 0;
      d.deltacomp = paycomp;
      d.addblk = 0;
      d.addblklen = 0;
      if (verbose)
	fprintf(vfp, "writing delta rpm...\n");
      writedeltarpm(&d, 0);
      if (seqfile)
        write_seqfile(&d, seqfile);
      sigh = xfree(sigh);
      h = xfree(h);
      d.seq = xfree(d.seq);
      d.seql = 0;
      d.lead = xfree(d.lead);
      d.leadl = 0;
      seq = xfree(seq);
      d.targetnevr = xfree(d.targetnevr);
      exit(0);
    }

  if (!alone)
    sigh = xfree(sigh);

  if (pinfo)
    {
      if (strcmp(nevr, nevr1) != 0)
	{
	  fprintf(stderr, "pinfo rpmlist1 (%s) does not match rpm (%s)\n", nevr1, nevr);
	  exit(1);
	}
      if (strcmp(nevr, nevr2) != 0)
	{
	  fprintf(stderr, "pinfo rpmlist2 (%s) does not match rpm (%s)\n", nevr2, nevr);
	  exit(1);
	}
    }
  filenames = headexpandfilelist(h, &filecnt);
  fileflags = headint32(h, TAG_FILEFLAGS, (int *)0);
  filemd5s = headstringarray(h, TAG_FILEMD5S, (int *)0);
  filerdevs = headint16(h, TAG_FILERDEVS, (int *)0);
  filesizes = headint32(h, TAG_FILESIZES, (int *)0);
  filemodes = headint16(h, TAG_FILEMODES, (int *)0);
  fileverify = headint32(h, TAG_FILEVERIFY, (int *)0);
  filelinktos = headstringarray(h, TAG_FILELINKTOS, (int *)0);
  filecolors = headint32(h, TAG_FILECOLORS, (int *)0);

  if ((digestalgoarray = headint32(h, TAG_FILEDIGESTALGO, (int *)0)))
    {
      digestalgo = digestalgoarray[0];
      free(digestalgoarray);
    }
  if (digestalgo != 1 && digestalgo != 8)
    {
      fprintf(stderr, "Unknown digest type: %d\n", digestalgo);
      exit(1);
    }

/***************************************************************************/

  if (alone)
    {
      if (verbose)
	fprintf(vfp, "reading rpm...\n");
      nfd = fd;
      fd = -1;
      d.h = h;
      h = 0;
      stream = 0;	/* sorry! */
    }
  else
    {
      if (verbose)
	fprintf(vfp, "reading new rpm...\n");
      rpmname = argv[argc - 2];
      if (!strcmp(rpmname, "-"))
	nfd = 0;
      else if ((nfd = open(rpmname, O_RDONLY)) < 0)
	{
	  perror(rpmname);
	  exit(1);
	}
      if (read(nfd, rpmlead, 96) != 96 || rpmlead[0] != 0xed || rpmlead[1] != 0xab || rpmlead[2] != 0xee || rpmlead[3] != 0xdb)
	{
	  fprintf(stderr, "%s: not a rpm\n", rpmname);
	  exit(1);
	}
      if (rpmlead[4] != 0x03 || rpmlead[0x4e] != 0 || rpmlead[0x4f] != 5)
	{
	  fprintf(stderr, "%s: not a v3 rpm or not new header styles\n", rpmname);
	  exit(1);
	}
      sigh = readhead(nfd, 1);
      if (!sigh)
	{
	  fprintf(stderr, "could not read signature header\n");
	  exit(1);
	}
      d.h = readhead(nfd, 0);
      if (!d.h)
	{
	  fprintf(stderr, "could not read header\n");
	  exit(1);
	}
    }
  rpmMD5Init(&fullmd5);
  rpmMD5Update(&fullmd5, rpmlead, 96);
  rpmMD5Update(&fullmd5, sigh->intro, 16);
  rpmMD5Update(&fullmd5, sigh->data, sigh->cnt * 16 + sigh->dcnt);
  rpmMD5Update(&fullmd5, d.h->intro, 16);
  rpmMD5Update(&fullmd5, d.h->data, d.h->cnt * 16 + d.h->dcnt);
  if (rpmonly)
    {
      /* add new header to cpio */
      addtocpio(&newcpio, &newcpiolen, d.h->intro, 16);
      addtocpio(&newcpio, &newcpiolen, d.h->data, 16 * d.h->cnt + d.h->dcnt);
    }
  fullsize = 96 + 16 + sigh->cnt * 16 + sigh->dcnt + 16 + d.h->cnt * 16 + d.h->dcnt;
  newbz = cfile_open(CFILE_OPEN_RD, nfd, 0, CFILE_COMP_XX, CFILE_LEN_UNLIMITED, (cfile_ctxup)rpmMD5Update, &fullmd5);
  if (!newbz)
    {
      fprintf(stderr, "payload open failed\n");
      exit(1);
    }
  if (cfile_detect_rsync(newbz))
    {
      fprintf(stderr, "detect_rsync failed\n");
      exit(1);
    }
  targetcomp = newbz->comp;
  if ((payloadflags = headstring(d.h, TAG_PAYLOADFLAGS)) != 0)
    if (*payloadflags >= '1' && *payloadflags <= '9')
      targetcomp = cfile_setlevel(targetcomp, *payloadflags - '0');
  if (paycomp == CFILE_COMP_XX)
    paycomp = targetcomp;
  if (addblkcomp == CFILE_COMP_XX)
    addblkcomp = targetcomp;

  if (stream)
    {
      memset(&sd, 0, sizeof(sd));
      sd.xnewdata = newcpio;
      sd.xnewdatal = newcpiolen;
      sd.newf = newbz;
      sd.bsize = stream;
      sd.old = xmalloc(sd.bsize);
      sd.new = xmalloc(sd.bsize);
      if (addblkcomp != -1)
        sd.cfa = cfile_open(CFILE_OPEN_WR, CFILE_IO_ALLOC, &d.addblk, addblkcomp, CFILE_LEN_UNLIMITED, 0, 0);
      sd.cfi = cfile_open(CFILE_OPEN_WR, CFILE_IO_ALLOC, &d.indata, CFILE_COMP_UN, CFILE_LEN_UNLIMITED, 0, 0);
      oldcpio = (void *)&sd;
      oldcpiolen = 0;
      sd.stepd = mkdiff_step_setup(DELTAMODE_HASH | (addblkcomp == -1 ? DELTAMODE_NOADDBLK : 0));
    }
  else
    {
      while ((l = newbz->read(newbz, buf, sizeof(buf))) > 0)
	addtocpio(&newcpio, &newcpiolen, (unsigned char *)buf, l);
      if (l < 0)
	{
	  fprintf(stderr, "payload read failed\n");
	  exit(1);
	}
    }

/***************************************************************************/

  if (rpmonly)
    {
      /* add old header to cpio */
      addtocpio(&oldcpio, &oldcpiolen, h->intro, 16);
      addtocpio(&oldcpio, &oldcpiolen, h->data, 16 * h->cnt + h->dcnt);
      rpmMD5Update(&seqmd5, h->intro, 16);
      rpmMD5Update(&seqmd5, h->data, 16 * h->cnt + h->dcnt);
      bfd = cfile_open(CFILE_OPEN_RD, fd, 0, CFILE_COMP_XX, CFILE_LEN_UNLIMITED, (cfile_ctxup)rpmMD5Update, &seqmd5);
    }
  else if (alone)
    bfd = cfile_open(CFILE_OPEN_RD, CFILE_IO_BUFFER, newcpio, CFILE_COMP_UN, newcpiolen, 0, 0);
  else
    bfd = cfile_open(CFILE_OPEN_RD, fd, 0, CFILE_COMP_XX, CFILE_LEN_UNLIMITED, 0, 0);
  if (!bfd)
    {
      fprintf(stderr, "payload open failed\n");
      exit(1);
    }
  if (verbose && !alone)
    fprintf(vfp, "reading old rpm...\n");
  if (rpmonly)
    {
      while ((l = bfd->read(bfd, buf, sizeof(buf))) > 0)
	addtocpio(&oldcpio, &oldcpiolen, (unsigned char *)buf, l);
    }
  else
    {
      namebufl = 1;
      namebuf = xmalloc(namebufl);
      cpiopos = oldcpiolen;
      oldadjust = oldcpiolen;
      for (;;)
	{
	  unsigned int size, nsize, lsize, nlink, rdev, hsize;

	  if (bfd->read(bfd, &cph, sizeof(cph)) != sizeof(cph))
	    {
	      fprintf(stderr, "payload read failed (header)\n");
	      exit(1);
	    }
	  cpiopos += sizeof(cph);
	  if (memcmp(cph.magic, "070701", 6))
	    {
	      fprintf(stderr, "bad cpio archive\n");
	      exit(1);
	    }
	  size = cpion(cph.filesize);
	  nsize = cpion(cph.namesize);
	  nlink = cpion(cph.nlink);
	  nsize += (4 - ((nsize + 2) & 3)) & 3;
	  if (nsize > namebufl)
	    {
	      namebuf = xrealloc(namebuf, nsize);
	      namebufl = nsize;
	    }
	  if (bfd->read(bfd, namebuf, nsize) != nsize)
	    {
	      fprintf(stderr, "payload read failed (name)\n");
	      exit(1);
	    }
	  cpiopos += nsize;
	  namebuf[nsize - 1] = 0;
	  if (!strcmp(namebuf, "TRAILER!!!"))
	    break;
	  cpiocnt++;
	  np = namebuf;
	  if (*np == '.' && np[1] == '/')
	    np += 2;
	  skip = 1;
	  /* look it up in the header */
	  for (i = 0; i < filecnt; i++)
	    if (!strcmp(filenames[i] + (filenames[i][0] == '/' ? 1 : 0), np))
	      break;
	  rdev = lsize = 0;
	  if (i == filecnt)
	    {
	      if (verbose > 1)
	        fprintf(vfp, "%s not found in rpm header\n", np);
	      skipped_notfound++;
	    }
	  else if (prunes && is_pruned(np))
	    {
	      if (verbose > 1)
	        fprintf(vfp, "skipping %s: pruned\n", np);
	      skipped_pruned++;
	    }
	  else if (pinfo && S_ISREG(filemodes[i]) && is_unpatched(np, files1, nfiles1, files2, nfiles2, filemd5s[i]))
	    {
	      if (verbose > 1)
	        fprintf(vfp, "skipping %s: unpatched but different\n", np);
	      skipped_unpatched++;
	    }
	  else if (S_ISREG(filemodes[i]))
	    {
	      if (size != filesizes[i])
		{
		  if (verbose > 1)
		    fprintf(vfp, "skipping %s: size missmatch\n", np);
		  skipped_badsize++;
		}
	      else if ((fileflags[i] & (FILE_CONFIG|FILE_MISSINGOK|FILE_GHOST)) != 0)
		{
		  if (verbose > 1)
		    fprintf(vfp, "skipping %s: bad file flags\n", np);
		  skipped_fileflags++;
		}
	      else if ((fileverify[i] & (VERIFY_MD5|VERIFY_FILESIZE)) != (VERIFY_MD5|VERIFY_FILESIZE))
		{
		  if (verbose > 1)
		    fprintf(vfp, "skipping %s: bad verify flags %x\n", np, fileverify[i]);
		  skipped_verifyflags++;
		}
	      else if (filecolors && (filecolors[i] & (RPMFC_ELF32 | RPMFC_ELF64)) != 0 && !in_multilib_dir(np))
		{
		  if (verbose > 1)
		    fprintf(vfp, "skipping %s: colored file in non-multilib dir\n", np);
		  skipped_multilib++;
		}
	      else
		{
		  if (verbose > 1)
		    fprintf(vfp, "USING FILE %s\n", np);
		  lsize = size;
		  skip = 0;
		}
	    }
	  else if (S_ISLNK(filemodes[i]))
	    {
	      if (verbose > 1)
	        fprintf(vfp, "USING SYMLINK %s\n", np);
	      lsize = strlen(filelinktos[i]);
	      skip = 0;
	    }
	  else
	    {
	      if (verbose > 1)
	        fprintf(vfp, "USING ELEMENT %s\n", np);
	      if (S_ISBLK(filemodes[i]) || S_ISCHR(filemodes[i]))
		rdev = filerdevs[i];
	      skip = 0;
	    }

	  if (i == filecnt)
	    hsize = 0;
	  else
	    {
	      hsize = 2 + strlen(np) + 1;
	      hsize += (4 - ((hsize + 2) & 3)) & 3;
	      hsize += S_ISREG(filemodes[i]) ? filesizes[i] : S_ISLNK(filemodes[i]) ? strlen(filelinktos[i]) : 0;
	      hsize += (4 - (hsize & 3)) & 3;
	    }
	  l = nsize + size;
	  l += (4 - (l & 3)) & 3;

	  if (!skip)
	    {
	      unsigned char cpiobuf[110 + 3];
	      int ns = strlen(np);
	      if (oldcpiolen != cpiopos - sizeof(cph) - nsize)
		{
oaretry1:
		  if ((offadjn & 15) == 0)
		    offadjs = xrealloc2(offadjs, offadjn + 16, 2 * sizeof(unsigned int));
		  if (oldcpiolen - oldadjust >= 0x80000000)
		    {
		      offadjs[2 * offadjn] = 0x7fffffff;
		      offadjs[2 * offadjn + 1] = 0;
		      oldadjust += 0x7fffffff;
		      offadjn++;
		      goto oaretry1;
		    }
		  offadjs[2 * offadjn] = oldcpiolen - oldadjust;
		  oldadjust = oldcpiolen;
		  if (cpiopos - sizeof(cph) - nsize >= oldcpiolen)
		    {
		      drpmuint a = cpiopos - sizeof(cph) - nsize - oldcpiolen;
		      if (a >= 0x80000000)
			{
			  offadjs[2 * offadjn + 1] = 0x7fffffff;
			  cpiopos -= 0x7fffffff;
			  offadjn++;
			  goto oaretry1;
			}
		      offadjs[2 * offadjn + 1] = a;
		    }
	          else
		    {
		      drpmuint a = oldcpiolen - (cpiopos - sizeof(cph) - nsize);
		      if (a >= 0x80000000)
			{
			  offadjs[2 * offadjn + 1] = (unsigned int)-((int)0x7fffffff);
			  cpiopos += 0x7fffffff;
			  offadjn++;
			  goto oaretry1;
			}
		      offadjs[2 * offadjn + 1] = (unsigned int)(-(int)a);
		    }
		  offadjn++;
		  cpiopos = oldcpiolen + sizeof(cph) + nsize;
		}
	      sprintf((char *)cpiobuf, "07070100000000%08x00000000000000000000000100000000%08x0000000000000000%08x%08x%08x00000000./", filemodes[i], lsize, devmajor(rdev), devminor(rdev), ns + 3);
	      addtocpio(&oldcpio, &oldcpiolen, cpiobuf, 112);
	      addtocpio(&oldcpio, &oldcpiolen, (unsigned char *)np, ns + 1);
	      ns += 3 - 2;
	      for (; ns & 3 ; ns++)
		addtocpio(&oldcpio, &oldcpiolen, (unsigned char *)"", 1);
	      rpmMD5Update(&seqmd5, (unsigned char *)np, strlen(np) + 1);
	      rpmMD5Update32(&seqmd5, filemodes[i]);
	      rpmMD5Update32(&seqmd5, lsize);
	      rpmMD5Update32(&seqmd5, rdev);
	      if (S_ISLNK(filemodes[i]))
		{
		  addtocpio(&oldcpio, &oldcpiolen, (unsigned char *)filelinktos[i], lsize);
		  for (; lsize & 3 ; lsize++)
		    addtocpio(&oldcpio, &oldcpiolen, (unsigned char *)"", 1);
		  skip = 1;
		  rpmMD5Update(&seqmd5, (unsigned char *)filelinktos[i], strlen(filelinktos[i]) + 1);
		}
	      if (S_ISREG(filemodes[i]) && lsize)
		{
		  unsigned char fmd5[32];
		  if (digestalgo == 1)
		    {
		      parsemd5(filemd5s[i], fmd5);
		      rpmMD5Update(&seqmd5, fmd5, 16);
		    }
		  else
		    {
		      parsesha256(filemd5s[i], fmd5);
		      rpmMD5Update(&seqmd5, fmd5, 32);
		    }
		}
	      addtoseq(i);
	    }
	  else
	    skipped_all++;
	  l = l2 = size;
	  while (l > 0)
	    {
	      l3 = l > sizeof(buf) ? sizeof(buf) : l;
	      if (bfd->read(bfd, buf, l3) != l3)
		{
		  fprintf(stderr, "payload read failed (data)\n");
		  exit(1);
		}
	      cpiopos += l3;
	      if (!skip)
		addtocpio(&oldcpio, &oldcpiolen, (unsigned char *)buf, l3);
	      l -= l3;
	    }
	  if ((l2 & 3) != 0)
	    {
	      l2 = 4 - (l2 & 3);
	      if (bfd->read(bfd, buf, l2) != l2)
		{
		  fprintf(stderr, "payload read failed (pad)\n");
		  exit(1);
		}
	      cpiopos += l2;
	      if (!skip)
		addtocpio(&oldcpio, &oldcpiolen, (unsigned char *)"\0\0\0", l2);
	    }
	}
      namebuf = xfree(namebuf);
      namebufl = 0;
      addtocpio(&oldcpio, &oldcpiolen, (unsigned char *)"07070100000000000000000000000000000000000000010000000000000000000000000000000000000000000000000000000b00000000TRAILER!!!\0\0\0\0", 124);
      if (verbose)
	{
	  fprintf(vfp, "files used:    %4d/%d = %.1f%%\n", (cpiocnt - skipped_all), cpiocnt, (cpiocnt - skipped_all) * 100. / (cpiocnt ? cpiocnt : 1));
	  fprintf(vfp, "files skipped: %4d/%d = %.1f%%\n", skipped_all, cpiocnt, skipped_all * 100. / (cpiocnt ? cpiocnt : 1));
	  if (skipped_notfound)
	    fprintf(vfp, "  not found:    %4d/%d = %.1f%%\n", skipped_notfound, skipped_all, skipped_notfound * 100. / skipped_all);
	  if (skipped_pruned)
	    fprintf(vfp, "  pruned:       %4d/%d = %.1f%%\n", skipped_pruned, skipped_all, skipped_pruned * 100. / skipped_all);
	  if (skipped_unpatched)
	    fprintf(vfp, "  unpatched:    %4d/%d = %.1f%%\n", skipped_unpatched, skipped_all, skipped_unpatched * 100. / skipped_all);
	  if (skipped_badsize)
	    fprintf(vfp, "  bad size:     %4d/%d = %.1f%%\n", skipped_badsize, skipped_all, skipped_badsize * 100. / skipped_all);
	  if (skipped_fileflags)
	    fprintf(vfp, "  file flags:   %4d/%d = %.1f%%\n", skipped_fileflags, skipped_all, skipped_fileflags * 100. / skipped_all);
	  if (skipped_verifyflags)
	    fprintf(vfp, "  verify flags: %4d/%d = %.1f%%\n", skipped_verifyflags, skipped_all, skipped_verifyflags * 100. / skipped_all);
	  if (skipped_multilib)
	    fprintf(vfp, "  colored-not-in-multidir: %4d/%d = %.1f%%\n", skipped_multilib, skipped_all, skipped_multilib * 100. / skipped_all);
	}
      addtoseq(-1);
      if (verbose > 1)
	{
	  fprintf(vfp, "sequence: ");
	  for (i = 0; i < (seqp + 1) / 2; i++)
	    fprintf(vfp, "%02x", seq[i]);
	  fprintf(vfp, "\n");
	}
    }
  bfd->close(bfd);

  if (stream)
    {
      /* finish */
      sd.oldeof = 1;
      addtocpio(&oldcpio, &oldcpiolen, 0, 0);
      if (sd.cfa)
        d.addblklen = sd.cfa->close(sd.cfa);
      d.inlen = sd.cfi->close(sd.cfi);
      sd.cfa = 0;
      sd.cfi = 0;
      instr = sd.instr;
      sd.instr = 0;
      instrlen = sd.instrlen;
      sd.instrlen = 0;
      mkdiff_step_free(sd.stepd);
      oldcpio = 0;
    }

  /* close old rpm */
  /* fd == -1 in "alone" mode */
  if (fd != -1 && strcmp(argv[argc - 3 + alone], "-") != 0)
    close(fd);

  rpmMD5Final(seqmd5res, &seqmd5);

  fileflags = xfree(fileflags);
  filemd5s = xfree(filemd5s);
  filerdevs = xfree(filerdevs);
  filesizes = xfree(filesizes);
  filemodes = xfree(filemodes);
  fileverify = xfree(fileverify);
  filelinktos = xfree(filelinktos);
  filenames = xfree(filenames);
  filecolors = xfree(filecolors);
  h = xfree(h);

  /* close new rpm */
  fullsize += newbz->bytes;
  if (newbz->close(newbz))
    {
      fprintf(stderr, "junk at end of payload\n");
      exit(1);
    }
  if (strcmp(rpmname, "-") != 0)
    close(nfd);
  rpmMD5Final(fullmd5res, &fullmd5);

/****************************************************************/

  payformat = headstring(d.h, TAG_PAYLOADFORMAT);
  if (!payformat || strcmp(payformat, "cpio") != 0)
    {
      fprintf(stderr, "payload format is not cpio\n");
      exit(1);
    }
  if (!stream)
    {
      if (verbose)
	fprintf(vfp, "creating diff...\n");
      d.addblk = 0;
      d.addblklen = 0;
      mkdiff(DELTAMODE_HASH | (addblkcomp == -1 ? DELTAMODE_NOADDBLK : 0), oldcpio, oldcpiolen, newcpio, newcpiolen, &instr, &instrlen, (unsigned char **)0, (unsigned int *)0, (addblkcomp == CFILE_COMP_BZ ? &d.addblk : 0), (addblkcomp == CFILE_COMP_BZ ? &d.addblklen : 0), (unsigned char **)0, (unsigned int *)0);
    }

/****************************************************************/

  if (verbose)
    fprintf(vfp, "writing delta rpm...\n");
  if (!stream && addblkcomp != -1 && addblkcomp != CFILE_COMP_BZ)
    createaddblock(instr, instrlen, &d, oldcpio, newcpio, addblkcomp);
  d.name = argv[argc - 1];
  d.version = 0x444c5430 + version;
  memcpy(d.rpmlead, rpmlead, 96);
  d.leadl = 96 + 16 + sigh->cnt * 16 + sigh->dcnt;
  d.lead = xmalloc(d.leadl);
  memcpy(d.lead, rpmlead, 96);
  memcpy(d.lead + 96, sigh->intro, 16);
  memcpy(d.lead + 96 + 16, sigh->data, d.leadl - 96 - 16);
  convertinstr(instr, instrlen, &d);
  if (!stream)
    indatalist = createindatalist(instr, instrlen, &d, newcpio);
  d.nevr = nevr;
  d.seql = 16 + (seqp + 1) / 2;
  d.seq = xmalloc(d.seql);
  memcpy(d.seq, seqmd5res, 16);
  memcpy(d.seq + 16, seq, d.seql - 16);
  memcpy(d.targetmd5, fullmd5res, 16);
  d.targetnevr = headtonevr(d.h);
  d.targetsize = fullsize;
  d.targetcomp = targetcomp;
  d.targetcomppara = 0;
  d.targetcompparalen = 0;
  d.compheadlen = rpmonly ? 16 + 16 * d.h->cnt + d.h->dcnt : 0;
  d.offadjn = offadjn;
  d.offadjs = offadjs;
  d.payformatoff = payformat - (char *)d.h->dp;
  d.outlen = oldcpiolen;
  if (rpmonly)
    d.h = xfree(d.h);
  d.deltacomp = paycomp;
  writedeltarpm(&d, indatalist);
  if (seqfile)
    write_seqfile(&d, seqfile);
  d.addblk = xfree(d.addblk);
  d.addblklen = 0;
  instr = xfree(instr);
  instrlen = 0;
  oldcpio = xfree(oldcpio);
  newcpio = xfree(newcpio);
  sigh = xfree(sigh);
  d.h = xfree(d.h);
  indatalist = xfree(indatalist);
  d.indata = xfree(d.indata);
  d.in = xfree(d.in);
  d.out = xfree(d.out);
  d.inn = d.outn = 0;
  d.seq = xfree(d.seq);
  d.seql = 0;
  d.lead = xfree(d.lead);
  d.leadl = 0;
  nevr = xfree(nevr);
  seq = xfree(seq);
  sd.old = xfree(sd.old);
  sd.new = xfree(sd.new);
  offadjs = xfree(offadjs);
  d.targetnevr = xfree(d.targetnevr);
  exit(0);
}

