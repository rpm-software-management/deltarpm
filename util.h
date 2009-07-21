/*
 * Copyright (c) 2004 Michael Schroeder (mls@suse.de)
 *
 * This program is licensed under the BSD license, read LICENSE.BSD
 * for further information
 */

extern void *xmalloc(size_t);
extern void *xmalloc2(size_t, size_t);
extern void *xcalloc(size_t, size_t);
extern void *xrealloc(void *, size_t);
extern void *xrealloc2(void *, size_t, size_t);
extern void *xfree(void *);
extern ssize_t xread(int fd, void *buf, size_t l);
extern int parsehex(char *s, unsigned char *buf, int len);
extern void parsemd5(char *s, unsigned char *md5);
extern void parsesha256(char *s, unsigned char *sha256); 
