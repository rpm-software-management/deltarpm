#define _XOPEN_SOURCE 500

#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <fcntl.h>

static inline int
elf16(unsigned char *buf, int le)
{
  if (le)
    return buf[0] | buf[1] << 8;
  return buf[0] << 8 | buf[1];
}

static inline unsigned int
elf32(unsigned char *buf, int le)
{
  if (le)
    return buf[0] | buf[1] << 8 | buf[2] << 16 | buf[3] << 24;
  return buf[0] << 24 | buf[1] << 16 | buf[2] << 8 | buf[3];
}

static inline unsigned int
elf64(unsigned char *buf, int le, int is64)
{
  if (is64)
    {
      buf += le ? 4 : 0;
      if (buf[0] || buf[1] || buf[2] || buf[3])
	return ~0;
      buf += le ? -4 : 4;
    }
  if (le)
    return buf[0] | buf[1] << 8 | buf[2] << 16 | buf[3] << 24;
  return buf[0] << 24 | buf[1] << 16 | buf[2] << 8 | buf[3];
}

int
is_prelinked(int fd, unsigned char *buf, int l)
{
  int le, is64;
  off_t soff;
  int snum, ssiz;
  int i, stridx;
  unsigned char *sects, *strsect;
  unsigned int slen;
  unsigned int o;

  if (l < 0x34)
    return 0;
  if (buf[0] != 0x7f || buf[1] != 'E' || buf[2] != 'L' || buf[3] != 'F')
    return 0;
  is64 = buf[4] == 2;
  le = buf[5] != 2;
  if (is64 && l < 0x40)
    return 0;
  soff = elf64(is64 ? buf + 40 : buf + 32, le, is64);
  if (soff == (off_t)~0)
    return 0;
  ssiz = elf16(buf + (is64 ? 0x40 - 6 : 0x34 - 6), le);
  if (ssiz < (is64 ? 64 : 40) || ssiz >= 32768)
    return 0;
  snum = elf16(buf + (is64 ? 0x40 - 4 : 0x34 - 4), le);
  stridx = elf16(buf + (is64 ? 0x40 - 2 : 0x34 - 2), le);
  if (stridx >= snum)
    return 0;
  sects = malloc(snum * ssiz);
  if (!sects)
    return 0;
  if (pread(fd, sects, snum * ssiz, soff) != snum * ssiz)
    {
      free(sects);
      return 0;
    }
  strsect = sects + stridx * ssiz;
  if (elf32(strsect + 4, le) != 3)
    {
      free(sects);
      return 0;
    }
  soff = elf64(is64 ? strsect + 24 : strsect + 16, le, is64);
  slen = elf64(is64 ? strsect + 32 : strsect + 20, le, is64);
  if (soff == (off_t)~0 || slen == ~0 || (int)slen < 0)
    {
      free(sects);
      return 0;
    }
  strsect = malloc(slen);
  if (!strsect)
    {
      free(sects);
      return 0;
    }
  if (pread(fd, strsect, slen, soff) != slen)
    {
      free(sects);
      free(strsect);
      return 0;
    }
  for (i = 0; i < snum; i++)
    {
      o = elf32(sects + i * ssiz, le);
      if (o > slen)
	continue;
      /* printf("sect #%d %s\n", i, strsect + o); */
      if (o + 18 <= slen && memcmp(strsect + o, ".gnu.prelink_undo", 18) == 0)
	break;
    }
  free(strsect);
  free(sects);
  return i == snum ? 0 : 1;
}


pid_t prelink_pid;

int
prelinked_open(char *name)
{
  pid_t pid;
  int fd, status;
  struct stat stb;
  char template[21];

  if (stat("/usr/sbin/prelink", &stb))
    {
      perror("/usr/sbin/prelink");
      fprintf(stderr, "prelink not installed, cannot undo prelinking");
      exit(1);
    }
  strcpy(template, "/tmp/deltarpm.XXXXXX");
  if ((fd = mkstemp(template)) == -1)
    {
      perror("mkstemp");
      exit(1);
    }
  close(fd);    /* prelink renames another tmpfile over our file */
  pid = fork();
  if (pid == (pid_t)(-1))
    {
      perror("fork");
      exit(1);
    }
  if (!pid)
    {
      execl("/usr/sbin/prelink", "prelink", "-o", template, "-u", name, (char *)0);
      perror("/usr/sbin/prelink");
      _exit(1);
    }
  while (waitpid(pid, &status, 0) == (pid_t)-1)
    ;
  if ((fd = open(template, O_RDONLY)) == -1)
    {
      perror(template);
      exit(1);
    }
  unlink(template);
  return fd; 
}

