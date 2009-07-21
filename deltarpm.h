/*
 * Copyright (c) 2005 Michael Schroeder (mls@suse.de)
 *
 * This program is licensed under the BSD license, read LICENSE.BSD
 * for further information
 */

#ifdef DELTARPM_64BIT
typedef uint64_t     drpmuint;
typedef int64_t      drpmint;
#else
typedef unsigned int drpmuint;
typedef int          drpmint;
#endif

struct fileblock
{
  struct rpmhead *h;
  int cnt;
  char **filenames;
  unsigned int *filemodes;
  unsigned int *filesizes;
  unsigned int *filerdevs;
  char **filelinktos;
  char **filemd5s;
  int digestalgo;
};


#define SEQCHECK_MD5   (1<<0)
#define SEQCHECK_SIZE  (1<<1)

struct openfile;

struct seqdescr {
  int i;
  int cpiolen;
  int datalen;
  drpmuint off;
  struct openfile *f;
};


struct deltarpm {
  char *name;
  int deltacomp;
  unsigned char rpmlead[96];
  struct rpmhead *h;
  int version;
  char *nevr;
  unsigned char *seq;
  unsigned int seql;
  char *targetnevr;
  unsigned char targetmd5[16];
  unsigned int targetsize;
  unsigned int targetcomp;
  unsigned char *targetcomppara;
  unsigned int targetcompparalen;
  unsigned char *lead;
  unsigned int leadl;
  unsigned int payformatoff;
  drpmuint     paylen;
  unsigned int inn;
  unsigned int outn;
  unsigned int *in;
  unsigned int *out;
  drpmuint     outlen;
  unsigned int addblklen;
  unsigned char *addblk;
  drpmuint     inlen;
  unsigned char *indata;

  unsigned int compheadlen;
  unsigned int *offadjs;
  unsigned int offadjn;

  struct fileblock fb;
  struct seqdescr *sdesc;
  int nsdesc;
  unsigned char *cpiodata;

  struct deltarpm *next;
  struct deltarpm *prev;
  unsigned char *outptr;
  int combaddblk;
};

/* from readdeltarpm.c */
int headtofb(struct rpmhead *h, struct fileblock *fb);
struct seqdescr *expandseq(unsigned char *seq, int seql, int *nump, struct fileblock *fb, int (*checkfunc)(char *, int, unsigned char *, unsigned int));
void readdeltarpm(char *n, struct deltarpm *d, struct cfile **cfp);

/* from writedeltarpm.c */
void writedeltarpm(struct deltarpm *d, unsigned char **indatalist);

