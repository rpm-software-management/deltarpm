/*
 * Copyright (c) 2004,2005 Michael Schroeder (mls@suse.de)
 *
 * This program is licensed under the BSD license, read LICENSE.BSD
 * for further information
 */

#define _XOPEN_SOURCE 500
#ifdef DELTARPM_64BIT
# define _LARGEFILE64_SOURCE
#endif

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <unistd.h>
#include <string.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <sys/wait.h>

#include <bzlib.h>
#include <zlib.h>
#include <lzma.h>

#include "util.h"
#include "md5.h"
#include "sha256.h"
#include "rpmhead.h"
#include "cpio.h"
#include "cfile.h"
#include "deltarpm.h"
#include "prelink.h"

#define BLKSHIFT 13
#define BLKSIZE  (1 << BLKSHIFT)
#define BLKMASK  ((1 << BLKSHIFT) - 1)

#define SEQCHECK_MD5   (1<<0)
#define SEQCHECK_SIZE  (1<<1)

#ifndef RPMDUMPHEADER
# define RPMDUMPHEADER "rpmdumpheader"
#endif


/*****************************************************************
 * openfile, maintain a set of opened files, close descriptors if
 * limit is reached.
 */

struct openfile {
  struct openfile *prev;
  struct openfile *next;
  char *name;
  int fd;
  unsigned int off;
  struct seqdescr *sd;
};

struct openfile *openfiles;
struct openfile *openfilestail;
int nopenfile;
int maxopenfile = 50;



struct openfile *
newopen(struct seqdescr *sd, struct fileblock *fb)
{
  int fd;
  char *name;
  struct openfile *of;
  struct stat stb;

  name = fb->filenames[sd->i];
  if ((fd = open(name, O_RDONLY)) == -1)
    {
      perror(name);
      fprintf(stderr, "cannot reconstruct rpm from disk files\n");
      exit(1);
    }
  if (fstat(fd, &stb) == 0 && stb.st_size != fb->filesizes[sd->i])
    {
      unsigned char buf[128];
      if (is_prelinked(fd, buf, pread(fd, buf, 128, (off_t)0)))
	{
	  close(fd);
	  return 0;
	}
    }
  if (nopenfile < maxopenfile)
    {
      of = xmalloc(sizeof(*of));
      nopenfile++;
    }
  else
    {
      of = openfiles;
      openfiles = of->next;
      if (openfiles)
	openfiles->prev = 0;
      else
	openfilestail = 0;
      of->sd->f = 0;
      // printf("closing %s\n", of->name);
      close(of->fd);
    }
  // printf("opening %s\n", name);
  of->fd = fd;
  of->name = name;
  of->off = 0;
  of->sd = sd;
  of->prev = of->next = 0;
  if (openfilestail)
    {
      openfilestail->next = of;
      of->prev = openfilestail;
      openfilestail = of;
    }
  else
    openfiles = openfilestail = of;
  sd->f = of;
  return of;
}

/*****************************************************************
 * blk stuff, block contents creation and paging
 */

#define BLK_FREE     0
#define BLK_CORE_REC 1
#define BLK_CORE_ONE 2
#define BLK_PAGE     3

struct blk {
  struct blk *next;
  int type;
  int id;
  union {
    unsigned int off;
    unsigned char *buf;
  } e;
};

struct blk *coreblks;
struct blk *freecoreblks;
struct blk *pageblks;
int ncoreblk = 0;
int npageblk = 0;
int ndropblk = 0;

int maxcoreblk = 5000;

unsigned int *maxblockuse;	/* last time the block will be used */
struct blk **vmem;

unsigned char *cpiodata;
int csdesc = -1;
char *symdata;

char *fromrpm;
int fromrpm_raw;
struct cfile *outfp;
unsigned int outfpleft;
drpmuint outfpleft_raw;
int outfpid;


int pagefd = -1;


void (*fillblock_method)(struct blk *b, int id, struct seqdescr *sdesc, int nsdesc, struct fileblock *fb, int idx);

void
pageoutblock(struct blk *cb, int idx)
{
  struct blk *b;

  // printf("pageoutblock %d\n", cb->id);
  for (b = pageblks; b; b = b->next)
    if (b->id == cb->id)
      {
        vmem[b->id] = b;
        return;
      }
  for (b = pageblks; b; b = b->next)
    if (maxblockuse[b->id] < idx)
      break;
  if (!b)
    {
      b = xmalloc(sizeof(*b));
      b->next = pageblks;
      b->type = BLK_PAGE;
      b->e.off = npageblk;
      pageblks = b;
      npageblk++;
      if (pagefd < 0)
	{
	  char tmpname[80];
	  sprintf(tmpname, "/tmp/deltarpmpageXXXXXX");
#ifdef DELTARPM_64BIT
	  pagefd = mkstemp64(tmpname);
#else
	  pagefd = mkstemp(tmpname);
#endif
	  if (pagefd < 0)
	    {
	      fprintf(stderr, "could not create page area\n");
	      exit(1);
	    }
	  unlink(tmpname);
	}
    }
  b->id = cb->id;
#ifdef DELTARPM_64BIT
  if (pwrite64(pagefd, cb->e.buf, BLKSIZE, (off64_t)b->e.off * BLKSIZE) != BLKSIZE)
    {
      perror("page area write");
      exit(1);
    }
#else
  if (pwrite(pagefd, cb->e.buf, BLKSIZE, (off_t)b->e.off * BLKSIZE) != BLKSIZE)
    {
      perror("page area write");
      exit(1);
    }
#endif
  vmem[b->id] = b;
}

void
pageinblock(struct blk *cb, struct blk *b)
{
  if (b->type != BLK_PAGE)
    abort();
#ifdef DELTARPM_64BIT
  if (pread64(pagefd, cb->e.buf, BLKSIZE, (off64_t)b->e.off * BLKSIZE) != BLKSIZE)
    {
      perror("page area read");
      exit(1);
    }
#else
  if (pread(pagefd, cb->e.buf, BLKSIZE, (off_t)b->e.off * BLKSIZE) != BLKSIZE)
    {
      perror("page area read");
      exit(1);
    }
#endif
  cb->id = b->id;
  cb->type = BLK_CORE_ONE;
  vmem[cb->id] = cb;
}

struct blk *
newcoreblk(void)
{
  struct blk *b;
  b = xmalloc(sizeof(*b) + BLKSIZE);
  b->next = coreblks;
  b->type = BLK_FREE;
  b->e.buf = (unsigned char *)(b + 1);
  coreblks = b;
  ncoreblk++;
  // printf("created new coreblk, have now %d\n", ncoreblk);
  return b;
}

void
pushblock(struct blk *nb, int idx)
{
  struct blk *b;

  b = freecoreblks;
  if (b)
    {
      freecoreblks = b->next;
      b->next = coreblks;
      coreblks = b;
    }
  if (!b && ncoreblk < maxcoreblk)
    b = newcoreblk();
  if (!b)
    {
      /* could not find in-core place */
      if (nb->type == BLK_CORE_ONE)
        pageoutblock(nb, idx);
      else
	vmem[nb->id] = 0;
      return;
    }
  b->type = nb->type;
  b->id = nb->id;
  memcpy(b->e.buf, nb->e.buf, BLKSIZE);
  vmem[b->id] = b;
}

void
createcpiohead(struct seqdescr *sd, struct fileblock *fb)
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
    {
      symdata = fb->filelinktos[i];
      lsize = strlen(fb->filelinktos[i]);
    }
  if (S_ISBLK(fb->filemodes[i]) || S_ISCHR(fb->filemodes[i]))
    rdev = fb->filerdevs[i];
  sprintf((char *)cpiodata, "07070100000000%08x00000000000000000000000100000000%08x0000000000000000%08x%08x%08x00000000./%s%c%c%c%c", fb->filemodes[i], lsize, devmajor(rdev), devminor(rdev), (int)strlen(np) + 3, np, 0, 0, 0, 0);
}

int nprelink = 0;

void
fillblock_prelink(struct blk *b, int id, struct seqdescr *sd, struct fileblock *fb, int idx)
{
  int xid = id;
  drpmuint off;
  struct stat stb;
  char *name;
  int fd = -1;
  int isp = 0;
  int l;
  unsigned char buf[128];
  unsigned char *bp, saveblk[BLKSIZE];

  /* go to first block that doesn't start in the middle of a
   * prelinked file */
  off = id << BLKSHIFT;
  for (;;)
    {
      while (sd->off > off)
        sd--;
      /* now sd contains off */
      if (sd->i == -1 || sd->datalen == 0 || sd->off + sd->cpiolen >= off)
	break;
      if (S_ISLNK(fb->filemodes[sd->i]))
	break;
      /* off in regular file, check if prelinked */
      name = fb->filenames[sd->i];
      if ((fd = open(name, O_RDONLY)) == -1)
	{
	  perror(name);
	  fprintf(stderr, "cannot reconstruct rpm from disk files\n");
	  exit(1);
	}
      if (fstat(fd, &stb) != 0 || stb.st_size == fb->filesizes[sd->i])
	break;
      if (!is_prelinked(fd, buf, pread(fd, buf, 128, (off_t)0)))
	break;
      close(fd);
      fd = -1;
      /* rewind blocks until we leave the file */
      do
	{
	  id--;
	  off = id << BLKSHIFT;
	}
      while (sd->off + sd->cpiolen < off);
    }
  /* ok, got id, sd and maybe fd. create blocks. */
  l = BLKSIZE;
  bp = b->e.buf;
  if (fd != -1)
    {
      unsigned int u = off - (sd->off + sd->cpiolen);
      if (u && u < fb->filesizes[sd->i])
	{
	  if (lseek(fd, (off_t)u, SEEK_SET) == (off_t)-1)
	    {
	      fprintf(stderr, "%s: seek error\n", fb->filenames[sd->i]);
	      fprintf(stderr, "cannot reconstruct rpm from disk files\n");
	      exit(1);
	    }
	}
    }
  for (;;)
    {
      while (l)
	{
	  while (off >= sd->off + sd->cpiolen + sd->datalen)
	    {
	      if (fd != -1)
		{
		  close(fd);
		  fd = -1;
		}
	      sd++;
	    }
	  if (off < sd->off + sd->cpiolen)
	    {
	      int o = off - sd->off;
	      int l2 = l > sd->cpiolen - o ? sd->cpiolen - o : l;
	      createcpiohead(sd, fb);
	      memcpy(bp, cpiodata + o, l2);
	      bp += l2;
	      off += l2;
	      l -= l2;
	    }
	  if (!l)
	    break;
	  if (sd->i == -1)
	    {
	      memset(bp, 0, l);
	      bp += l;
	      off += l;
	      l -= l;
	    }
	  else if (S_ISLNK(fb->filemodes[sd->i]))
	    {
	      int o = off - (sd->off + sd->cpiolen);
	      char *ln = fb->filelinktos[sd->i];
	      int l2 = strlen(ln) - o;
	      if (l2 < 0)
		l2 = 0;
	      if (l2 > l)
		l2 = l;
	      if (l2)
		memcpy(bp, ln + o, l2);
	      bp += l2;
	      off += l2;
	      l -= l2;
	      o += l2;
	      l2 = l > sd->datalen - o ? sd->datalen - o : l;
	      if (l2 > 0)
		{
		  memset(bp, 0, l2);
		  bp += l2;
		  off += l2;
		  l -= l2;
		}
	    }
	  else if (sd->datalen)
	    {
	      int o = off - (sd->off + sd->cpiolen);
	      int l2;
	      if (o < fb->filesizes[sd->i])
		{
		  l2 = l > fb->filesizes[sd->i] - o ? fb->filesizes[sd->i] - o : l;
		  if (fd == -1)
		    {
		      name = fb->filenames[sd->i];
		      isp = 0;
		      if ((fd = open(name, O_RDONLY)) == -1)
			perror(name);
		      else if (fstat(fd, &stb) == 0 && stb.st_size != fb->filesizes[sd->i] && is_prelinked(fd, buf, pread(fd, buf, 128, (off_t)0)))
			{
			  close(fd);
			  fd = prelinked_open(name);
			  nprelink++;
			  isp = 1;
			}
		      if (fd == -1)
			{
			  fprintf(stderr, "cannot reconstruct rpm from disk files\n");
			  exit(1);
			}
		    }
		  if (read(fd, bp, l2) != l2)
		    {
		      fprintf(stderr, "%s: read error\n", fb->filenames[sd->i]);
		      fprintf(stderr, "(tried to read %d bytes from offset %d\n", l2, o);
		      exit(1);
		    }
		  bp += l2;
		  off += l2;
		  l -= l2;
		  o += l2;
		}
	      if (o >= fb->filesizes[sd->i])
		{
		  if (fd)
		    {
		      close(fd);
		      fd = -1;
		    }
		  l2 = l > sd->datalen - o ? sd->datalen - o : l;
		  if (l2)
		    memset(bp, 0, l2);
		  bp += l2;
		  off += l2;
		  l -= l2;
		}
	    }
	}

      b->type = BLK_CORE_ONE;
      b->id = id;
      if (id == xid)
	memcpy(saveblk, b->e.buf, BLKSIZE);
      else if (maxblockuse[b->id] > idx || (maxblockuse[b->id] == idx && id > xid))
	pushblock(b, idx);
      /* finished block */
      if (fd == -1 || !isp)
	break;
      l = BLKSIZE;
      bp = b->e.buf;
      id++;
      off = id << BLKSHIFT;
    }
  if (id < xid)
    {
      fprintf(stderr, "internal error, could not reach block %d (%d)\n", xid, id);
      exit(1);
    }
  if (fd != -1)
    close(fd);		/* never prelinked */
  memcpy(b->e.buf, saveblk, BLKSIZE);
  b->type = BLK_CORE_ONE;
  b->id = xid;
}

void
fillblock_disk(struct blk *b, int id, struct seqdescr *sdesc, int nsdesc, struct fileblock *fb, int idx)
{
  drpmuint off;
  unsigned int u;
  struct seqdescr *sd;
  int i;
  unsigned int l, l2;
  unsigned char *bp;

  l = BLKSIZE;
  bp = b->e.buf;
  off = id << BLKSHIFT;
  i = csdesc >= 0 ? csdesc : 0;
  for (sd = sdesc + i; i > 0 && sd->off > off; i--, sd--)
    ;
  for (; i < nsdesc; i++, sd++)
    if (sd->off <= off && sd->off + sd->cpiolen + sd->datalen > off)
      break;
  if (i == nsdesc)
    {
      fprintf(stderr, "fillblock_disk: block %d out of range\n", id);
      exit(1);
    }
  if (i != csdesc)
    {
      csdesc = i;
      createcpiohead(sd, fb);
    }
  i = sd->i;
  while (l > 0)
    {
      if (off < sd->off + sd->cpiolen)
	{
	  u = off - sd->off;
	  l2 = sd->cpiolen - u;
	  if (l2 > l)
	    l2 = l;
	  memcpy(bp, cpiodata + u, l2);
	  bp += l2;
	  off += l2;
	  l -= l2;
	  continue;
	}
      if (i == -1)
	{
	  memset(bp, 0, l);
	  l = 0;
	  break;
	}
      if (off < sd->off + sd->cpiolen + sd->datalen)
	{
	  u = off - (sd->off + sd->cpiolen);
	  if (S_ISLNK(fb->filemodes[i]))
	    {
	      l2 = sd->datalen - u;
	      if (l2 > l)
		l2 = l;
	      if (u > strlen(symdata))
		memset(bp, 0, l2);
	      else
		strncpy((char *)bp, symdata + u, l2);
	    }
	  else if (u < fb->filesizes[i])
	    {
	      struct openfile *of;
	      l2 = fb->filesizes[i] - u;
	      if (l2 > l)
		l2 = l;
	      if (!(of = sd->f))
		of = newopen(sd, fb);
	      if (!of)
		{
		  fillblock_prelink(b, id, sd, fb, idx);
		  csdesc = -1;
		  return;
		}
	      if (of->next)
		{
		  of->next->prev = of->prev;
		  if (of->prev)
		    of->prev->next = of->next;
		  else
		    openfiles = of->next;
		  of->next = 0;
		  of->prev = openfilestail;
		  openfilestail->next = of;
		  openfilestail = of;
		}
	      if (of->off != u)
		{
		  if (lseek(of->fd, (off_t)u, SEEK_SET) == (off_t)-1)
		    {
		      fprintf(stderr, "%s: seek error\n", of->name);
		      fprintf(stderr, "cannot reconstruct rpm from disk files\n");
		      exit(1);
		    }
		}
	      if (read(of->fd, bp, l2) != l2)
		{
		  fprintf(stderr, "%s: read error\n", of->name);
		  fprintf(stderr, "(tried to read %d bytes from offset %d)\n", l2, u);
		  fprintf(stderr, "cannot reconstruct rpm from disk files\n");
		  exit(1);
		}
	      of->off = u + l2;
	    }
	  else
	    {
	      l2 = sd->datalen - u;
	      if (l2 > l)
		l2 = l;
	      memset(bp, 0, l2);
	    }
	  bp += l2;
	  off += l2;
	  l -= l2;
	  continue;
        }
      csdesc++;
      sd++;
      createcpiohead(sd, fb);
      i = sd->i;
    }
  b->id = id;
  b->type = BLK_CORE_REC;
}

void
fillblock_rawrpm(struct blk *b, int id, struct seqdescr *sdesc, int nsdesc, struct fileblock *fb, int idx)
{
  unsigned char *bp;
  unsigned int l2;

  for (;;)
    {
      bp = b->e.buf;
      l2 = outfpleft_raw > BLKSIZE ? BLKSIZE : outfpleft_raw;
      if (outfp->read(outfp, bp, l2) != l2)
	{
	  fprintf(stderr, "read error");
	  exit(1);
	}
      outfpleft_raw -= l2;
      if (l2 < BLKSIZE)
	memset(bp + l2, 0, BLKSIZE - l2);
      b->type = BLK_CORE_ONE;
      b->id = outfpid++;
      if (b->id == id)
	 return;
      if (b->id > id)
	{
	  fprintf(stderr, "internal error, cannot rewind blocks (%d %d)\n", b->id, id);
	  exit(1);
	}
      if (maxblockuse[b->id] > idx)
	pushblock(b, idx);
    }
}

void
fillblock_rpm(struct blk *b, int id, struct seqdescr *sdesc, int nsdesc, struct fileblock *fb, int idx)
{
  unsigned int size, nsize;
  unsigned char *bp;
  char *np;
  int i;
  unsigned int l, l2, u;
  struct seqdescr *sd;
  struct cpiophys cph;
  static char *namebuf;
  static int namebufl;
  char skipbuf[4096];

  l = BLKSIZE;
  bp = b->e.buf;
  for (;;)
    {
      if (outfpleft)
	{
	  sd = sdesc + csdesc;
	  if (outfpleft > sd->datalen)
	    {
	      u = sd->cpiolen + sd->datalen - outfpleft;
	      l2 = sd->cpiolen - u;
	      if (l2 > l)
		l2 = l;
	      memcpy(bp, cpiodata + u, l2);
	      bp += l2;
	      outfpleft -= l2;
	      l -= l2;
	    }
	  if (l && outfpleft)
	    {
	      l2 = outfpleft;
	      if (l2 > l)
		l2 = l;
	      if (S_ISLNK(fb->filemodes[sd->i]))
		{
		  strncpy((char *)bp, symdata, l2);
		  if (strlen(symdata) < l2)
		    symdata += strlen(symdata);
		  else
		    symdata += l2;
		}
	      else
		{
		  if (outfp->read(outfp, bp, l2) != l2)
		    {
		      fprintf(stderr, "read error");
		      exit(1);
		    }
		}
	      bp += l2;
	      outfpleft -= l2;
	      l -= l2;
	    }
	}
      if (l && csdesc >= 0 && sdesc[csdesc].i == -1)
	{
	  memset(bp, 0, l); /* blocks are empty after trailer */
	  l = 0;
	}
      if (l == 0)
	{
	  b->type = BLK_CORE_ONE;
	  b->id = outfpid++;
	  if (b->id == id)
	     return;
	  if (b->id > id)
	    {
	      fprintf(stderr, "internal error, cannot rewind blocks (%d %d)\n", b->id, id);
	      exit(1);
	    }
	  if (maxblockuse[b->id] > idx)
	    pushblock(b, idx);
	  l = BLKSIZE;
	  bp = b->e.buf;
	  continue;
	}
      csdesc++;
      sd = sdesc + csdesc;
      i = sd->i;
      if (i == -1)
	{
	  createcpiohead(sd, fb);
	  outfpleft = sd->cpiolen + sd->datalen;
	  continue;
	}
      for (;;)
	{
	  if (outfp->read(outfp, &cph, sizeof(cph)) != sizeof(cph))
	    {
	      fprintf(stderr, "read error");
	      exit(1);
	    }
	  if (memcmp(cph.magic, "070701", 6))
	    {
	      fprintf(stderr, "read error: bad cpio archive\n");
	      exit(1);
	    }
	  size = cpion(cph.filesize);
	  nsize = cpion(cph.namesize);
	  nsize += (4 - ((nsize + 2) & 3)) & 3;
	  if (nsize > namebufl)
	    {
	      namebuf = xrealloc(namebuf, nsize);
	      namebufl = nsize;
	    }
	  if (outfp->read(outfp, namebuf, nsize) != nsize)
	    {
	      fprintf(stderr, "read failed (name)\n");
	      exit(1);
	    }
	  namebuf[nsize - 1] = 0;
	  if (!strcmp(namebuf, "TRAILER!!!"))
	    {
	      fprintf(stderr, "cpio end reached, bad rpm\n");
	      exit(1);
	    }
	  np = namebuf;
	  if (*np == '.' && np[1] == '/')
	    np += 2;
	  if (!strcmp(fb->filenames[i][0] == '/' ? fb->filenames[i] + 1 : fb->filenames[i], np))
	    break;
	  if (size & 3)
	    size += 4 - (size & 3);
	  while (size > 0)
	    {
	      l2 = size > sizeof(skipbuf) ? sizeof(skipbuf) : size;
	      if (outfp->read(outfp, skipbuf, l2) != l2)
		{
		  fprintf(stderr, "read failed (name)\n");
		  exit(1);
		}
	      size -= l2;
	    }
	}
      createcpiohead(sd, fb);
      if (size & 3)
	size += 4 - (size & 3);
      if (!S_ISREG(fb->filemodes[i]))
	{
	  while (size > 0)
	    {
	      l2 = size > sizeof(skipbuf) ? sizeof(skipbuf) : size;
	      if (outfp->read(outfp, skipbuf, l2) != l2)
		{
		  fprintf(stderr, "read failed (data skip)\n");
		  exit(1);
		}
	      size -= l2;
	    }
	}
      else if (size != sd->datalen)
	{
	  fprintf(stderr, "cpio data size mismatch, bad rpm\n");
	  exit(1);
	}
      outfpleft = sd->cpiolen + sd->datalen;
    }
}


/* construct the block "id". Note that the tupel (idx, id) will
 * only get bigger, so we use this to recycly no longer needed
 * blocks */

struct blk *
getblock(int id, struct seqdescr *sdesc, int nsdesc, struct fileblock *fb, int idx)
{
  struct blk *b, **bb;
  struct blk *pb;
  static int cleanup_cnt;

// printf("%d %d %d\n", idx, id, maxblockuse[id]);
  b = vmem[id];
  if (b && (b->type == BLK_CORE_REC || b->type == BLK_CORE_ONE))
    return b;

  b = freecoreblks;
  if (b)
    {
      freecoreblks = b->next;
      b->next = coreblks;
      coreblks = b;
    }

  if (!b && ncoreblk < maxcoreblk && (++cleanup_cnt & 7) != 0)
    b = newcoreblk();

  if (!b)
    {
      for (bb = &coreblks; (b = *bb) != 0; bb = &b->next)
	{
	  if (maxblockuse[b->id] < idx || (maxblockuse[b->id] == idx && b->id < id))
	    {
	      *bb = b->next;
	      vmem[b->id] = 0;
	      b->type = BLK_FREE;
	      b->next = freecoreblks;
	      freecoreblks = b;
	    }
	  else
	    bb = &b->next;
	}
      b = freecoreblks;
      if (b)
	{
	  freecoreblks = b->next;
	  b->next = coreblks;
	  coreblks = b;
	}
    }

  if (!b && ncoreblk < maxcoreblk)
    b = newcoreblk();
  if (!b)
    {
      /* use first created block */
      for (bb = &coreblks; (b = *bb); bb = &b->next)
	if (b->next == 0)
	  break;
      *bb = 0;
      b->next = coreblks;
      coreblks = b;
      if (b->type == BLK_CORE_ONE)
	pageoutblock(b, idx);
      else
	{
	  vmem[b->id] = 0;
	  ndropblk++;
	}
      b->type = BLK_FREE;
    }

  /* got destination block, now fill it with data */
  pb = vmem[id];
  if (pb && pb->type == BLK_PAGE)
    {
      pageinblock(b, pb);
      return b;
    }
  fillblock_method(b, id, sdesc, nsdesc, fb, idx);
  vmem[id] = b;
  return b;
}

int
cfile_write_uncomp(struct cfile *f, void *buf, int len)
{
  int l2;
  if (!len)
    return 0;
  l2 = len > f->len ? f->len : len;
  if (fwrite(buf, l2, 1, (FILE *)f->fp) != 1)
    return -1;
  if (l2 && f->ctxup)
    f->ctxup(f->ctx, buf, l2);
  f->len -= l2;
  if (f->len)
    return l2;
  f = cfile_open(CFILE_OPEN_WR, CFILE_IO_REOPEN, f, f->comp, CFILE_LEN_UNLIMITED, f->ctxup, f->ctx);
  if (!f)
    {
      fprintf(stderr, "payload re-open error\n");
      exit(1);
    }
  if (f->write(f, buf + l2, len - l2) != len - l2)
    return -1;
  return len;
}

typedef struct {
  union {
    MD5_CTX md5ctx;
    SHA256_ctx sha256ctx;
  } ctx;
} DIG_CTX;


static inline void
DIG_Init(DIG_CTX *ctx, int digestalgo)
{
  if (digestalgo == 1)
    rpmMD5Init(&ctx->ctx.md5ctx);
  else if (digestalgo == 8)
    SHA256_init(&ctx->ctx.sha256ctx);
}

static inline void
DIG_Update(DIG_CTX *ctx, int digestalgo, unsigned char const *buf, unsigned len)
{
  if (digestalgo == 1)
    rpmMD5Update(&ctx->ctx.md5ctx, buf, len);
  else if (digestalgo == 8)
    SHA256_update(&ctx->ctx.sha256ctx, buf, len);
}

static inline void
DIG_Final(DIG_CTX *ctx, int digestalgo, unsigned char *digest)
{
  if (digestalgo == 1)
    rpmMD5Final(digest, &ctx->ctx.md5ctx);
  else if (digestalgo == 8)
    {
      SHA256_final(&ctx->ctx.sha256ctx);
      SHA256_digest(&ctx->ctx.sha256ctx, digest);
    }
  else
    *digest = 0;
}

static inline int
DIG_Len(int digestalgo)
{
  if (digestalgo == 1)
    return 16;
  if (digestalgo == 8)
    return 32;
  return 0;
}

int
checkprelinked(char *name, int digestalgo, unsigned char *hmd5, unsigned int size)
{
  int fd, l;
  unsigned char buf[4096];
  DIG_CTX ctx;
  unsigned char md5[32];

  nprelink++;
  if ((fd = prelinked_open(name)) < 0)
    {
      perror(name);
      return -1;
    }
  DIG_Init(&ctx, digestalgo);
  while (size && (l = read(fd, buf, sizeof(buf))) > 0)
    {
      if (l > size)
	l = size;
      DIG_Update(&ctx, digestalgo, buf, l);
      size -= l;
    }
  close(fd);
  DIG_Final(&ctx, digestalgo, md5);
  if (memcmp(md5, hmd5, DIG_Len(digestalgo)))
    {
      fprintf(stderr, "%s: contents have been changed\n", name);
      return -1;
    }
  return 0;
}

int
checkfilemd5(char *name, int digestalgo, unsigned char *hmd5, unsigned int size)
{
  int fd, l;
  unsigned char buf[4096];
  DIG_CTX ctx;
  unsigned char md5[32];
  struct stat stb;

  if ((fd = open(name, O_RDONLY)) < 0 || fstat(fd, &stb))
    {
      perror(name);
      return -1;
    }
  DIG_Init(&ctx, digestalgo);
  if (stb.st_size > size && (l = read(fd, buf, sizeof(buf))) > 0)
    {
      if (is_prelinked(fd, buf, l))
	{
	  close(fd);
	  return checkprelinked(name, digestalgo, hmd5, size);
	}
      if (l > size)
	l = size;
      DIG_Update(&ctx, digestalgo, buf, l);
      size -= l;
    }
  while (size && (l = read(fd, buf, sizeof(buf))) > 0)
    {
      if (l > size)
	l = size;
      DIG_Update(&ctx, digestalgo, buf, l);
      size -= l;
    }
  close(fd);
  DIG_Final(&ctx, digestalgo, md5);
  if (memcmp(md5, hmd5, DIG_Len(digestalgo)))
    {
      fprintf(stderr, "%s: contents have been changed\n", name);
      return -1;
    }
  return 0;
}

int
checkfilesize(char *name, int digestalgo, unsigned char *hmd5, unsigned int size)
{
  struct stat stb;
  unsigned char buf[128];
  int l;

  if (stat(name, &stb) == -1)
    {
      perror(name);
      return -1;
    }
  if (stb.st_size == size)
    return 0;
  if (stb.st_size > size)
    {
      int fd;
      fd = open(name, O_RDONLY);
      if (fd != -1 && (l = read(fd, buf, sizeof(buf))) > 0 && is_prelinked(fd, buf, l))
	{
	  close(fd);
	  return checkprelinked(name, digestalgo, hmd5, size);
	}
      if (fd != -1)
        close(fd);
    }
  fprintf(stderr, "%s: contents have been changed\n", name);
  return -1;
}

/*****************************************************************
 * main program
 */

int
main(int argc, char **argv)
{
  int c, i;
  char *deltarpm;
  struct rpmhead *h;
  int fd;
  struct cfile *bfp = 0;
  struct cfile *obfp;
  char *fnevr;
  unsigned int inn;
  unsigned int *in;
  unsigned int outn;
  unsigned int *out;
  drpmuint off, paywritten;
  struct fileblock fb;
  struct seqdescr *sdesc;
  int nsdesc;
  struct blk *lastblk = 0;
  int idx;
  int on;
  unsigned int len, l;
  int bs, be;
  unsigned char buf[4096];
  MD5_CTX wrmd5;
  unsigned char wrmd5res[16];
  int nofullmd5 = 0;
  FILE *ofp;
  int numblks;
  int percent = 0;
  int curpercent;
  int lastpercent = -1;
  int verbose = 0;
  int seqcheck = 0;
  int check = 0;
  int checkflags = 0;
  int info = 0;
  bz_stream addbz2strm;
  z_stream addgzstrm;
  int addblkcomp;
  unsigned char *addblkbuf = 0;
  unsigned char *b;
  int seqmatches = 1;
  FILE *vfp;
  struct deltarpm d;
  char *arch = 0;

  while ((c = getopt(argc, argv, "cCisvpr:a:")) != -1)
    {
      switch(c)
	{
	case 'v':
          verbose++;
	  break;
	case 'p':
          percent++;
	  break;
	case 'r':
	  fromrpm = optarg;
	  break;
	case 's':
	  check = 1;
	  seqcheck = 1;
	  break;
	case 'i':
	  info = 1;
	  break;
	case 'c':
	  checkflags = SEQCHECK_MD5;
	  check = 1;
	  break;
	case 'C':
	  checkflags = SEQCHECK_SIZE;
	  check = 1;
	  break;
	case 'a':
	  arch = optarg;
	  break;
	default:
	  fprintf(stderr, "usage: applydeltarpm [-r <rpm>] deltarpm rpm\n");
          exit(1);
	}
    }

  if (optind + (check || info ? 1 : 2) != argc)
    {
      fprintf(stderr, "usage: applydeltarpm [-r <rpm>] deltarpm rpm\n");
      exit(1);
    }
  if (checkflags && fromrpm)
    {
      fprintf(stderr, "on-disk checking does not work with the -r option.\n");
      exit(1);
    }

  vfp = !(check || info) && !strcmp(argv[argc - 1], "-") ? stderr : stdout;

  deltarpm = argv[optind];

  bfp = 0;
  if (seqcheck)
    {
      char *hex;
      int nevrl;

      if (info)
	{
	  fprintf(stderr, "need real delta-rpm for info\n");
	  exit(1);
	}
      memset(&d, 0, sizeof(d));
      d.name = deltarpm;
      d.seql = strlen(deltarpm);
      if (d.seql < 34 || (hex = strrchr(deltarpm, '-')) == 0)
	{
	  fprintf(stderr, "%s: bad sequence\n", deltarpm);
	  exit(1);
	}
      d.nevr = deltarpm;
      nevrl = hex - deltarpm;
      d.seql -= nevrl + 1;
      *hex++ = 0;
      d.seql = (d.seql + 1) / 2;
      d.seq = xmalloc(d.seql);
      if (parsehex(hex, d.seq, d.seql) != d.seql)
	{
	  fprintf(stderr, "bad sequence\n");
	  exit(1);
	}
    }
  else
    {
      if (verbose)
	fprintf(vfp, "reading deltarpm\n");
      readdeltarpm(deltarpm, &d, &bfp);
      nofullmd5 = !memcmp("\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0", d.targetmd5, 16);
#ifdef DELTARPM_64BIT
      if (d.outlen >= 0xffffffffULL << BLKSHIFT)
	{
	  fprintf(stderr, "cpio size too big\n");
	  exit(1);
	}
#endif
      numblks = (unsigned int)(d.outlen >> BLKSHIFT);
      if ((d.outlen & (BLKSIZE - 1)) != 0)
	numblks++;

      maxblockuse = xcalloc(numblks, sizeof(unsigned int));
      vmem = xcalloc(numblks, sizeof(struct blk *));

      if (verbose > 1)
	{
	  fprintf(vfp, "%llu bytes source payload size\n", (unsigned long long)d.outlen);
	  fprintf(vfp, "%llu bytes target payload size\n", (unsigned long long)d.paylen);
	  fprintf(vfp, "%llu bytes internal data size\n", (unsigned long long)d.inlen);
	  fprintf(vfp, "%u bytes add data size\n", d.addblklen);
	  fprintf(vfp, "%d blocks\n", numblks);
	  fprintf(vfp, "%d copy instructions\n", d.inn + d.outn);
	}
      off = 0;
      for (i = 0; i < d.outn; i++)
        {
	  off += (int)d.out[2 * i];
	  bs = off >> BLKSHIFT;
	  off += d.out[2 * i + 1];
	  be = (off - 1) >> BLKSHIFT;
	  for (; bs <= be; bs++)
	    maxblockuse[bs] = i;
	}
    }

  addblkcomp = CFILE_COMP_BZ;
  if (d.addblklen > 9 && d.addblk[0] == 0x1f && d.addblk[1] == 0x8b)
    addblkcomp = CFILE_COMP_GZ;
  else if (d.addblklen > 3 && (d.addblk[0] == 255 && d.addblk[1] == 'L' && d.addblk[2] == 'Z'))
    addblkcomp = CFILE_COMP_LZMA;
  else if (d.addblklen > 6 && (d.addblk[0] == 0xfd && d.addblk[1] == '7' && d.addblk[2] == 'z' && d.addblk[3] == 'X' && d.addblk[4] == 'Z'))
    addblkcomp = CFILE_COMP_XZ;
  if (info)
    {
      unsigned int *size;
      if (d.version)
	printf("deltarpm version: %c\n", d.version & 0xff);
      printf("deltarpm type: %s\n", d.h ? "standard" : d.targetcomp != CFILE_COMP_UN || d.inn != 0 || d.outn != 0 ? "rpm-only" : "rpm-only, no diff");
      printf("deltarpm compression: %s\n", cfile_comp2str(d.deltacomp));
      printf("sequence: %s-", d.nevr);
      for (i = 0; i < d.seql; i++)
	printf("%02x", d.seq[i]);
      putchar('\n');
      printf("source rpm: %s\n", d.nevr);
      if (d.h || d.targetcomp != CFILE_COMP_UN || d.inn != 0 || d.outn != 0)
        printf("source payload size: %llu\n", (unsigned long long)d.outlen);
      printf("target rpm: %s\n", d.targetnevr);
      if (d.h || d.targetcomp != CFILE_COMP_UN || d.inn != 0 || d.outn != 0)
	{
	  printf("target payload size: %llu\n", (unsigned long long)d.paylen);
	  if (d.targetcomp != CFILE_COMP_XX)
	    printf("target payload compression: %s\n", cfile_comp2str(d.targetcomp));
	}
      if (d.targetsize == 0)
	{
          struct rpmhead *dsigh = readhead_buf(d.lead + 96, d.leadl - 96, 0);
	  if (dsigh && (size = headint32(dsigh, 1000, (int *)0)) != 0)
	    {
	      d.targetsize = d.leadl + *size;
	      free(size);
	    }
	  xfree(dsigh);
	}
      if (d.targetsize)
        printf("target size: %u\n", d.targetsize);
      printf("target md5: ");
      for (i = 0; i < 16; i++)
	printf("%02x", d.targetmd5[i]);
      putchar('\n');
      if (d.h || d.targetcomp != CFILE_COMP_UN || d.inn != 0 || d.outn != 0)
	{
	  printf("internal data size: %llu\n", (unsigned long long)d.inlen);
	  printf("compressed add data size: %d\n", d.addblklen);
	  if (d.addblklen)
	    printf("compressed add data compression: %s\n", cfile_comp2str(addblkcomp));
	  printf("instructions: %d\n", d.inn + d.outn);
	}
      if (bfp)
        bfp->close(bfp);
      exit(0);
    }

  if (d.targetcompparalen)
    {
      fprintf(stderr, "deltarpm contains unknown compression parameters\n");
      exit(1);
    }

  if (!fromrpm)
    {
      pid_t pid;
      int pi[2];

      if (!seqcheck && !d.h)
	{
	  fprintf(stderr, "this deltarpm does not work from filesystem, use '-r <oldrpm>'.\n");
	  exit(1);
	}
      if (!seqcheck && !headstring(d.h, TAG_SOURCERPM))
	{
	  fprintf(stderr, "cannot reconstruct source rpms from filesystem\n");
	  exit(1);
	}
      if (pipe(pi))
	{
	  perror("pipe");
	  exit(1);
	}
      if ((pid = fork()) == (pid_t)-1)
	{
	  perror("fork");
	  exit(1);
	}
      if (pid == 0)
	{
	  close(pi[0]);
	  if (pi[1] != 1)
	    {
	      dup2(pi[1], 1);
	      close(pi[1]);
	    }
	  if (arch)
	    execlp(RPMDUMPHEADER, RPMDUMPHEADER, "-a", arch, d.nevr, (char *)0);
	  else
	    execlp(RPMDUMPHEADER, RPMDUMPHEADER, d.nevr, (char *)0);
	  perror(RPMDUMPHEADER);
	  _exit(1);
	}
      close(pi[1]);
      fd = pi[0];
    }
  else
    {
      unsigned char rpmlead[96];

      if ((fd = open(fromrpm, O_RDONLY)) < 0)
	{
	  perror(fromrpm);
	  exit(1);
	}
      if (read(fd, rpmlead, 96) != 96 || rpmlead[0] != 0xed || rpmlead[1] != 0xab || rpmlead[2] != 0xee || rpmlead[3] != 0xdb)
	{
	  fprintf(stderr, "%s: not a rpm\n", fromrpm);
	  exit(1);
	}
      if (rpmlead[4] != 0x03 || rpmlead[0x4e] != 0 || rpmlead[0x4f] != 5)
	{
	  fprintf(stderr, "%s: not a v3 rpm or not new header styles\n", fromrpm);
	  exit(1);
	}
      h = readhead(fd, 1);
      if (!h)
	{
	  fprintf(stderr, "could not read signature header\n");
	  exit(1);
	}
      if (!d.h)
	{
	  unsigned char *hmd5 = headbin(h, 1004, 16);
	  if (!hmd5 || memcmp(hmd5, d.seq, 16) != 0)
	    seqmatches = 0;
	  if (seqcheck)
	    {
	      /* we don't know if this is a rpm-only deltarpm or not,
               * so we assume yes if seqmatches is true */
	      if (seqmatches && d.seql == 16)
		seqcheck = 0;	/* assume rpm-only, no expandseq */
	      else
	        seqmatches = 1;	/* assume normal, run expandseq */
	    }
	}
      free(h);
    }
  h = readhead(fd, 0);
  if (!h)
    {
      if (fromrpm)
        fprintf(stderr, "could not read header\n");
      exit(1);
    }
  fnevr = headtonevr(h);
  if (strcmp(fnevr, (char *)d.nevr) != 0)
    {
      fprintf(stderr, "delta rpm made for %s, not %s\n", d.nevr, fnevr);
      exit(1);
    }
  if (!seqmatches)
    {
      fprintf(stderr, "rpm does not match the one used for creating the deltarpm\n");
      exit(1);
    }
  if (d.h || seqcheck)
    {
      int (*checkfunc)(char *, int, unsigned char *, unsigned int);
      if (headtofb(h, &fb))
	{
	  fprintf(stderr, "bad header\n");
	  exit(1);
	}
      checkfunc = 0;
      if ((checkflags & SEQCHECK_MD5) != 0)
	checkfunc = checkfilemd5;
      else if ((checkflags & SEQCHECK_SIZE) != 0)
	checkfunc = checkfilesize;
      sdesc = expandseq(d.seq, d.seql, &nsdesc, &fb, checkfunc);
      if (!sdesc)
	{
	  fprintf(stderr, "could not expand sequence data\n");
	  exit(1);
	}
    }
  else
    {
      nsdesc = 0;
      sdesc = 0;
    }
  if (!fromrpm)
    {
      int status;
      close(fd);
      wait(&status);
    }
  if (check)
    exit(0);

  l = 0;
  for (i = 0; i < nsdesc; i++)
    if (sdesc[i].cpiolen > l)
      l = sdesc[i].cpiolen;
  if (l < 124)
    l = 124;			/* room for tailer */
  cpiodata = xmalloc(l + 4);	/* extra room for padding */


  rpmMD5Init(&wrmd5);
  if (!strcmp(argv[optind + 1], "-"))
    ofp = stdout;
  else if ((ofp = fopen(argv[optind + 1], "w")) == 0)
    {
      perror(argv[optind + 1]);
      exit(1);
    }
  if (fwrite(d.lead, d.leadl, 1, ofp) != 1)
    {
      fprintf(stderr, "write error\n");
      exit(1);
    }
  if (!nofullmd5)
    rpmMD5Update(&wrmd5, d.lead, d.leadl);
  if (!d.h)
    fromrpm_raw = 1;

  if (fromrpm_raw && d.targetcomp == CFILE_COMP_UN && d.inn == 0 && d.outn == 0)
    {
      /* no diff, copy-through mode */
      if (fwrite(h->intro, 16, 1, ofp) != 1 || fwrite(h->data, 16 * h->cnt + h->dcnt, 1, ofp) != 1)
	{
	  fprintf(stderr, "write error\n");
	  exit(1);
	}
      rpmMD5Update(&wrmd5, h->intro, 16);
      rpmMD5Update(&wrmd5, h->data, 16 * h->cnt + h->dcnt);
      while ((l = read(fd, buf, sizeof(buf))) > 0)
	{
	  if (fwrite(buf, l, 1, ofp) != 1)
	    {
	      fprintf(stderr, "write error\n");
	      exit(1);
	    }
	  rpmMD5Update(&wrmd5, buf, l);
	}
      if (fflush(ofp) || (ofp != stdout && fclose(ofp) != 0))
	{
	  fprintf(stderr, "write error\n");
	  exit(1);
	}
      rpmMD5Final(wrmd5res, &wrmd5);
      if (nofullmd5)
        {
          struct rpmhead *dsigh = readhead_buf(d.lead + 96, d.leadl - 96, 0);
          if (dsigh)
            {
              unsigned char *hmd5 = headbin(dsigh, SIGTAG_MD5, 16);
              if (hmd5)
                {
                  if (memcmp(wrmd5res, hmd5, 16) != 0)
                    {
                      fprintf(stderr, "%s: md5 mismatch of result\n", deltarpm);
                      exit(1);
                    }
                }
              xfree(dsigh);
            }
        }
      else if (memcmp(wrmd5res, d.targetmd5, 16) != 0)
	{
	  fprintf(stderr, "%s: md5 mismatch of result\n", deltarpm);
	  exit(1);
	}
      exit(0);
    }

  if (!fromrpm_raw)
    {
      if (fwrite(d.h->intro, 16, 1, ofp) != 1)
	{
	  fprintf(stderr, "write error\n");
	  exit(1);
	}
      rpmMD5Update(&wrmd5, d.h->intro, 16);
      strncpy((char *)d.h->dp + d.payformatoff, "cpio", 4);
      if (fwrite(d.h->data, 16 * d.h->cnt + d.h->dcnt, 1, ofp) != 1)
	{
	  fprintf(stderr, "write error\n");
	  exit(1);
	}
      rpmMD5Update(&wrmd5, d.h->data, 16 * d.h->cnt + d.h->dcnt);
    }

  if (fromrpm)
    {
      if ((outfp = cfile_open(CFILE_OPEN_RD, fd, 0, CFILE_COMP_XX, CFILE_LEN_UNLIMITED, 0, 0)) == 0)
	{
	  fprintf(stderr, "%s: payload open failed\n", deltarpm);
	  exit(1);
	}
    }

  if (d.addblklen)
    {
      switch (addblkcomp)
	{
	case CFILE_COMP_GZ:
	  if (memcmp(d.addblk, "\037\213\010\0\0\0\0\0\0\003", 10) != 0)
	    {
	      fprintf(stderr, "addblk: unsupported gz stream\n");
	      exit(1);
	    }
	  addgzstrm.zalloc = NULL;
	  addgzstrm.zfree = NULL;
	  addgzstrm.opaque = NULL;
	  if (inflateInit2(&addgzstrm, -MAX_WBITS) != Z_OK)
	    {
	      fprintf(stderr, "addblk: inflateInit2 error\n");
	      exit(1);
	    }
	  addgzstrm.next_in = d.addblk + 10;
	  addgzstrm.avail_in = d.addblklen - 10;
	  break;
	default:
	  addbz2strm.bzalloc = NULL;
	  addbz2strm.bzfree = NULL;
	  addbz2strm.opaque = NULL;
	  if (BZ2_bzDecompressInit(&addbz2strm, 0, 0) != BZ_OK)
	    {
	      fprintf(stderr, "addblk: BZ2_bzDecompressInit error\n");
	      exit(1);
	    }
	  addbz2strm.next_in = (char *)d.addblk;
	  addbz2strm.avail_in = d.addblklen;
	  break;
	}
      addblkbuf = xmalloc(BLKSIZE);
    }

  obfp = cfile_open(CFILE_OPEN_WR, CFILE_IO_FILE, ofp, d.compheadlen ? CFILE_COMP_UN : d.targetcomp, CFILE_LEN_UNLIMITED, (cfile_ctxup)rpmMD5Update, &wrmd5);
  if (!obfp)
    {
      fprintf(stderr, "payload write error\n");
      exit(1);
    }
  if (d.compheadlen)
    {
      obfp->comp = d.targetcomp;
      obfp->len = d.compheadlen;
      obfp->write = cfile_write_uncomp;
    }
  if (fromrpm)
    fillblock_method = fillblock_rpm;
  else
    fillblock_method = fillblock_disk;
  if (fromrpm_raw)
    {
      fillblock_method = fillblock_rawrpm;
      if (outfp->unread(outfp, h->data, 16 * h->cnt + h->dcnt) || outfp->unread(outfp, h->intro, 16))
	{
	  fprintf(stderr, "could not unread header\n");
	  exit(1);
	}
      outfpleft_raw = d.outlen;
    }
  if (verbose)
    fprintf(vfp, "applying delta\n");
  idx = 0;
  paywritten = 0;
  inn = d.inn;
  outn = d.outn;
  in = d.in;
  out = d.out;
  off = 0;
  while (inn > 0)
    {
      on = *in++;
      if (on > outn)
	{
	  fprintf(stderr, "corrupt delta instructions\n");
	  exit(1);
	}
      while (on > 0)
	{
	  off += (int)*out++;
	  len = *out++;
	  paywritten += len;
	  outn--;
	  on--;
	  bs = off >> BLKSHIFT;
	  while (len > 0)
	    {
	      if (!lastblk || bs != lastblk->id)
		{
		  lastblk = vmem[bs];
		  if (!lastblk || lastblk->type == BLK_PAGE)
		    lastblk = getblock(bs, sdesc, nsdesc, &fb, idx);
		}
	      l = off & BLKMASK;
	      if (l + len > BLKSIZE)
		l = BLKSIZE - l;
	      else
		l = len;
	      b = lastblk->e.buf + (off & BLKMASK);
	      if (d.addblklen)
	        {
		  if (addblkcomp == CFILE_COMP_GZ)
		    {
		      addgzstrm.next_out = addblkbuf;
		      addgzstrm.avail_out = l;
		      inflate(&addgzstrm, Z_NO_FLUSH);
		      if (addgzstrm.avail_out != 0)
			{
			  fprintf(stderr, "addblk: inflate error\n");
			  exit(1);
			}
		    }
		  else
		    {
		      addbz2strm.next_out = (char *)addblkbuf;
		      addbz2strm.avail_out = l;
		      BZ2_bzDecompress(&addbz2strm);
		      if (addbz2strm.avail_out != 0)
			{
			  fprintf(stderr, "addblk: BZ2_bzDecompress error\n");
			  exit(1);
			}
		    }
		  for (i = 0; i < l; i++)
		    addblkbuf[i] += b[i];
		  b = addblkbuf;
	        }
	      if (obfp->write(obfp, b, l) != l)
		{
		  fprintf(stderr, "write error\n");
		  exit(1);
		}
	      len -= l;
	      off += l;
	      bs++;
	    }
	  idx++;
          if (percent)
	    {
	      if (d.paylen >= 0x1000000)
	        curpercent = (paywritten >> 8) * 100 / (d.paylen >> 8);
	      else if (d.paylen)
	        curpercent = paywritten * 100 / d.paylen;
	      else
	        curpercent = 0;
	      if (curpercent != lastpercent)
		{
		  if (percent > 1)
		    fprintf(vfp, "%d percent finished.\n", curpercent);
		  else
		    fprintf(vfp, "\r%d percent finished.", curpercent);
		  fflush(vfp);
		  lastpercent = curpercent;
		}
	    }
	}
      len = *in++;
      paywritten += len;
      while (len > 0)
	{
	  l = len > sizeof(buf) ? sizeof(buf) : len;
	  if (bfp->read(bfp, buf, l) != l)
	    {
	      fprintf(stderr, "%s: read error data area\n", deltarpm);
	      exit(1);
	    }
	  if (obfp->write(obfp, buf, l) != l)
	    {
	      fprintf(stderr, "write error\n");
	      exit(1);
	    }
	  len -= l;
	}
      inn--;
      if (percent)
	{
	  curpercent = paywritten * 100. / (d.paylen ? d.paylen : 1);
	  if (curpercent != lastpercent)
	    {
	      if (percent > 1)
		fprintf(vfp, "%d percent finished.\n", curpercent);
	      else
		fprintf(vfp, "\r%d percent finished.", curpercent);
	      fflush(vfp);
	      lastpercent = curpercent;
	    }
	}
    }
  if (percent > 1)
    fprintf(vfp, "100 percent finished.\n");
  else if (percent)
    fprintf(vfp, "\r100 percent finished.\n");
  if (obfp->close(obfp) == -1)
    {
      fprintf(stderr, "write error\n");
      exit(1);
    }
  if (fflush(ofp) || (ofp != stdout && fclose(ofp) != 0))
    {
      fprintf(stderr, "write error\n");
      exit(1);
    }
  if (outfp)
    outfp->close(outfp);
  if (bfp)
    bfp->close(bfp);
  if (d.addblklen)
    {
      if (addblkcomp == CFILE_COMP_GZ)
        inflateEnd(&addgzstrm);
      else
        BZ2_bzDecompressEnd(&addbz2strm);
    }
  if (verbose > 1)
    {
      fprintf(vfp, "used %d core pages\n", ncoreblk);
      fprintf(vfp, "used %d swap pages\n", npageblk);
      fprintf(vfp, "had to recreate %d core pages\n", ndropblk);
      if (nprelink)
        fprintf(vfp, "had to call prelink %d times\n", nprelink);
    }
  rpmMD5Final(wrmd5res, &wrmd5);
  if (nofullmd5)
    {
      struct rpmhead *dsigh = readhead_buf(d.lead + 96, d.leadl - 96, 0);
      if (dsigh)
        {
          unsigned char *hmd5 = headbin(dsigh, SIGTAG_MD5, 16);
          if (hmd5)
            {
              if (memcmp(wrmd5res, hmd5, 16) != 0)
                {
                  fprintf(stderr, "%s: md5 mismatch of result\n", deltarpm);
                  exit(1);
                }
            }
          xfree(dsigh);
        }
    }
  else if (memcmp(wrmd5res, d.targetmd5, 16) != 0)
    {
      fprintf(stderr, "%s: md5 mismatch of result\n", deltarpm);
      exit(1);
    }
  exit(0);
}
