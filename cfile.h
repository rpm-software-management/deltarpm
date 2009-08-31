/*
 * Copyright (c) 2005 Michael Schroeder (mls@suse.de)
 *
 * This program is licensed under the BSD license, read LICENSE.BSD
 * for further information
 */

#include <zlib.h>
#include <bzlib.h>
#include <lzma.h>

struct cfile {
  int fd;
  void *fp;
  int comp;
  int level;
  size_t len;
  unsigned char buf[4096];
  int bufN;
  int eof;
  void *ctx;
  void (*ctxup)(void *, unsigned char *, unsigned int);
  unsigned int crc;
  unsigned int crclen;
  size_t bytes;
  int nunread;
  unsigned char *unreadbuf;
  union {
    bz_stream bz;
    z_stream gz;
    lzma_stream lz;
  } strm;
  int (*read)(struct cfile *f, void *buf, int len);
  int (*write)(struct cfile *f, void *buf, int len);
  int (*close)(struct cfile *f);
  int (*unread)(struct cfile *f, void *buf, int len);
  int (*oldread)(struct cfile *f, void *buf, int len);
};

typedef void (*cfile_ctxup)(void *, unsigned char *, unsigned int);

#define CFILE_IO_FILE   (-2)
#define CFILE_IO_CFILE  (-3)
#define CFILE_IO_BUFFER (-4)
#define CFILE_IO_ALLOC  (-5)
#define CFILE_IO_NULL   (-6)

#define CFILE_IO_REOPEN     (-99)
#define CFILE_IO_PUSHBACK   (-100)	/* internal */

#define CFILE_COMP_XX (255)
#define CFILE_COMP_UN (0)
#define CFILE_COMP_GZ (1)
#define CFILE_COMP_BZ_20 (2)
#define CFILE_COMP_GZ_RSYNC (3)
#define CFILE_COMP_BZ_17 (4)
#define CFILE_COMP_LZMA (5)
#define CFILE_COMP_XZ (6)

#define CFILE_COMP_BZ CFILE_COMP_BZ_20

#define CFILE_MKCOMP(comp, level) ((comp) | ((level) << 8))
#define CFILE_COMPALGO(comp) ((comp) & 255)
#define CFILE_COMPLEVEL(comp) ((comp) >> 8 & 255)

#define CFILE_OPEN_RD ('r')
#define CFILE_OPEN_WR ('w')

#define CFILE_LEN_UNLIMITED ((size_t)-1)

#define CFILE_UNREAD_GET_LEN (-2)

#define CFILE_COPY_CLOSE_IN    (1 << 0)
#define CFILE_COPY_CLOSE_OUT   (1 << 1)
#define CFILE_COPY_CLOSE_INOUT (CFILE_COPY_CLOSE_IN|CFILE_COPY_CLOSE_OUT)

#define CFILE_UNREAD_GETBYTES  (-2)

struct cfile *cfile_open(int mode, int fd, void *fp, int comp, size_t len, void (*ctxup)(void *, unsigned char *, unsigned int), void *ctx);
int cfile_copy(struct cfile *in, struct cfile *out, int flags);
int cfile_detect_rsync(struct cfile *f);
char *cfile_comp2str(int comp);
int cfile_setlevel(int comp, int level);
