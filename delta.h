
#ifdef BSDIFF_SIZET
typedef size_t bsuint;
typedef ssize_t bsint;
#else
typedef unsigned int bsuint;
typedef int          bsint;
#endif

struct instr {
  bsuint copyout;
  bsuint copyin;
  bsuint copyinoff;
  bsuint copyoutoff;
};

void mkdiff(int mode, unsigned char *old, bsuint oldlen, unsigned char *new, bsuint newlen, struct instr **instrp, int *instrlenp, unsigned char **instrblkp, unsigned int *instrblklenp, unsigned char **addblkp, unsigned int *addblklenp, unsigned char **extrablkp, unsigned int *extrablklenp);

#define DELTAMODE_SUF  0
#define DELTAMODE_HASH 1

#define DELTAMODE_NOADDBLK 0x100
