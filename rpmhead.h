/*
 * Copyright (c) 2004 Michael Schroeder (mls@suse.de)
 *
 * This program is licensed under the BSD license, read LICENSE.BSD
 * for further information
 */

#define TAG_NAME        1000
#define TAG_VERSION     1001
#define TAG_RELEASE     1002
#define TAG_EPOCH       1003
#define TAG_ARCH        1022
#define TAG_FILENAMES   1027
#define TAG_FILESIZES   1028
#define TAG_FILEMODES   1030
#define TAG_FILERDEVS   1033
#define TAG_FILEMTIMES  1034
#define TAG_FILEMD5S    1035
#define TAG_FILELINKTOS 1036
#define TAG_FILEFLAGS   1037
#define TAG_SOURCERPM   1044
#define TAG_FILEVERIFY  1045
#define TAG_NOSOURCE    1051
#define TAG_NOPATCH     1052
#define TAG_DIRINDEXES  1116
#define TAG_BASENAMES   1117
#define TAG_DIRNAMES    1118
#define TAG_PAYLOADFORMAT 1124
#define TAG_PAYLOADCOMPRESSOR 1125
#define TAG_PAYLOADFLAGS 1126
#define TAG_FILECOLORS  1140
#define TAG_FILEDIGESTALGO 5011

#define SIGTAG_SIZE     1000
#define SIGTAG_MD5      1004
#define SIGTAG_GPG      1005
#define SIGTAG_PAYLOADSIZE 1007
#define SIGTAG_SHA1     269

#define FILE_CONFIG     (1 << 0)
#define FILE_MISSINGOK  (1 << 3)
#define FILE_GHOST      (1 << 6)
#define FILE_UNPATCHED  (1 << 10)

#define VERIFY_MD5      (1 << 0)
#define VERIFY_FILESIZE (1 << 1)

#define RPMFC_ELF32     (1 << 0)
#define RPMFC_ELF64     (1 << 1)

#define devmajor(rdev) (((rdev) >> 8) & 0xfff)
#define devminor(rdev) (((rdev) & 0xff) | (((rdev) >> 12) & 0xfff00))


struct rpmhead {
  int cnt;
  int dcnt;
  unsigned char *dp;
  unsigned char intro[16];
  unsigned char data[1];
};

extern struct rpmhead *readhead(int fd, int pad);
extern struct rpmhead *readhead_buf(unsigned char *buf, int len, int pad);
unsigned int *headint32(struct rpmhead *h, int tag, int *cnt);
unsigned int *headint16(struct rpmhead *h, int tag, int *cnt);
char *headstring(struct rpmhead *h, int tag);
unsigned char *headbin(struct rpmhead *h, int tag, int len);
char **headstringarray(struct rpmhead *h, int tag, int *cnt);
char **headexpandfilelist(struct rpmhead *h, int *cnt);
char *headtonevr(struct rpmhead *h);
int headtagtype(struct rpmhead *h, int tag);
