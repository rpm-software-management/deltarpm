/*
 * Copyright (c) 2005 Michael Schroeder (mls@suse.de)
 *
 * This program is licensed under the BSD license, read LICENSE.BSD
 * for further information
 */

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <stdint.h>
#include <unistd.h>

#include <zlib.h>
#include <bzlib.h>
#include <lzma.h>

#include "cfile.h"

/*****************************************************************
 *  generic input/output routines
 */

static int
cfile_readbuf(struct cfile *f, unsigned char *buf, int len)
{
  if (len < 0)
    return -1;
  if (f->len != CFILE_LEN_UNLIMITED && len > f->len)
    len = f->len;
  if (!len)
    {
      f->bufN = 0;
      return 0;
    }
  switch (f->fd)
    {
    case CFILE_IO_FILE:
      if (f->len == CFILE_LEN_UNLIMITED)
	{
	  len = fread(buf, 1, len, (FILE *)f->fp);
	  if (len == 0 && ferror((FILE *)f->fp))
	    return -1;
	}
      else if (fread(buf, len, 1, (FILE *)f->fp) != 1)
	return -1;
      break;
    case CFILE_IO_CFILE:
      len = ((struct cfile *)f->fp)->read((struct cfile *)f->fp, buf, len);
      break;
    case CFILE_IO_PUSHBACK:
      len = ((struct cfile *)f->fp)->read((struct cfile *)f->fp, buf, len);
      if (((struct cfile *)f->fp)->nunread == 0)
	{
	  struct cfile *cf = (struct cfile *)f->fp;
	  f->fp = cf->fp;
	  f->fd = cf->fd;
	  cf->close(cf);
	}
      break;
    case CFILE_IO_ALLOC:
      return -1;
    case CFILE_IO_BUFFER:
      memcpy(buf, f->fp, len);
      f->fp += len;
      break;
    case CFILE_IO_NULL:
      len = 0;
      break;
    default:
      len = read(f->fd, buf, len);
      break;
    }
  if (len < 0)
    return -1;
  if (f->len != CFILE_LEN_UNLIMITED)
    f->len -= len;
/*
  can't do this here because it cannot be undone...
  if (len && f->ctxup)
    f->ctxup(f->ctx, buf, len);
  f->bytes += len;
*/
  f->bufN = len;
  return len;
}

static int
cfile_writebuf(struct cfile *f, unsigned char *buf, int len)
{
  unsigned char **bp, *nb;

  if (len == 0)
    return 0;
  if (f->len != CFILE_LEN_UNLIMITED && f->len < len)
    return 0;
  switch (f->fd)
    {
    case CFILE_IO_FILE:
      if (fwrite(buf, len, 1, (FILE *)f->fp) != 1)
	len = -1;
      break;
    case CFILE_IO_CFILE:
      len = ((struct cfile *)f->fp)->write((struct cfile *)f->fp, buf, len);
      break;
    case CFILE_IO_BUFFER:
      memcpy(f->fp, buf, len);
      f->fp += len;
      break;
    case CFILE_IO_ALLOC:
      bp = (unsigned char **)f->fp;
      if (f->bytes + len < f->bytes)
	return -1;
      if (!f->bytes || (((f->bytes + len - 1) ^ (f->bytes - 1)) & ~0x1fff) != 0)
	{
	  int ns = (len + f->bytes + 0x1fff) & ~0x1fff;
	  if (ns < f->bytes + len)
	    return -1;
	  if (!f->bytes)
	    nb = malloc(ns);
	  else
	    nb = realloc(*bp, ns);
	  if (!nb)
	    return -1;
	  *bp = nb;
	}
      memcpy(*bp + f->bytes, buf, len);
      break;
    case CFILE_IO_NULL:
      break;
    default:
      len = write(f->fd, buf, len);
    }
  if (len == -1)
    return -1;
  if (f->len != CFILE_LEN_UNLIMITED)
    f->len -= len;
  if (len && f->ctxup)
    f->ctxup(f->ctx, buf, len);
  f->bytes += len;
  return len;
}

static void
cwclose_fixupalloc(struct cfile *f)
{
  unsigned char *n, **bp = (unsigned char **)f->fp;
  n = *bp;
  if (!n)
    return;
  n = realloc(n, f->bytes);
  if (n)
    *bp = n;
}


/*****************************************************************
 *  unread stuff
 */

static int
crread_ur(struct cfile *f, void *buf, int len)
{
  int l2;
  l2 = len > f->nunread ? f->nunread : len;
  if (l2)
    {
      memcpy(buf, f->unreadbuf, l2);
      buf += l2;
      len -= l2;
      f->nunread -= l2;
      if (f->ctxup)
	f->ctxup(f->ctx, f->unreadbuf, l2);
      f->bytes += l2;
      if (f->nunread)
	memmove(f->unreadbuf, f->unreadbuf + l2, f->nunread);
      if (!f->nunread && f->unreadbuf != f->buf)
	{
	  free(f->unreadbuf);
	  f->unreadbuf = 0;
	}
    }
  if (!f->nunread)
    {
      f->read = f->oldread;
      f->oldread = 0;
    }
  if (!len)
    return l2;
  len = f->read(f, buf, len);
  return len == -1 ? -1 : l2 + len;
}

static int
cfile_unreadbuf(struct cfile *f, void *buf, int len, int usebuf)
{
  unsigned char *newbuf;
  if (buf == 0 && len == CFILE_UNREAD_GETBYTES)
    return f->nunread;
  if (len < 0)
    return -1;
  if (len == 0)
    return 0;
  if (usebuf && (f->unreadbuf == 0 || f->unreadbuf == f->buf) && len <= sizeof(f->buf) - f->nunread)
    newbuf = f->buf;
  else
    {
      if (f->unreadbuf && f->unreadbuf != f->buf)
	newbuf = realloc(f->unreadbuf, f->nunread + len);
      else
	{
	  newbuf = malloc(f->nunread + len);
	  if (newbuf && f->nunread)
	    memcpy(newbuf, f->buf, f->nunread);
	}
      if (!newbuf)
	return -1;
    }
  if (f->nunread)
    memmove(newbuf + len, newbuf, f->nunread);
  memcpy(newbuf, buf, len);
  f->unreadbuf = newbuf;
  f->nunread += len;
  if (f->read != crread_ur)
    {
      f->oldread = f->read;
      f->read = crread_ur;
    }
  return 0;
}


/*****************************************************************
 *  bzip2 io
 */

static int
crread_bz(struct cfile *f, void *buf, int len)
{
  int ret, used;
  if (f->eof)
    return 0;
  f->strm.bz.avail_out = len;
  f->strm.bz.next_out = buf;
  for (;;)
    {
      if (f->strm.bz.avail_in == 0 && f->bufN)
        {
	  if (cfile_readbuf(f, f->buf, sizeof(f->buf)) == -1)
	    return -1;
          f->strm.bz.avail_in = f->bufN;
          f->strm.bz.next_in = (char *)f->buf;
        }
      used = f->strm.bz.avail_in;
      ret = BZ2_bzDecompress(&f->strm.bz);
      if (ret != BZ_OK && ret != BZ_STREAM_END)
        return -1;
      used -= f->strm.bz.avail_in;
      if (used && f->ctxup)
	f->ctxup(f->ctx, (unsigned char *)(f->strm.bz.next_in - used), used);
      f->bytes += used;
      if (ret == BZ_STREAM_END)
        {
          f->eof = 1;
          return len - f->strm.bz.avail_out;
        }
      if (f->strm.bz.avail_out == 0)
        return len;
      if (f->bufN == 0)
        return -1;
    }
}

static int
crclose_bz(struct cfile *f)
{
  int r;
  BZ2_bzDecompressEnd(&f->strm.bz);
  if (f->fd == CFILE_IO_CFILE && f->strm.bz.avail_in)
    {
      struct cfile *cf = (struct cfile *)f->fp;
      if (cf->unread(cf, f->strm.bz.next_in, f->strm.bz.avail_in) != -1)
        f->strm.bz.avail_in = 0;
    }
  r = (f->len != CFILE_LEN_UNLIMITED ? f->len : 0) + f->strm.bz.avail_in;
  if (f->unreadbuf != f->buf)
    free(f->unreadbuf);
  free(f);
  return r;
}

static struct cfile *
cropen_bz(struct cfile *f)
{
  if (BZ2_bzDecompressInit(&f->strm.bz, 0, 0) != BZ_OK)
    {
      free(f);
      return 0;
    }
  f->eof = 0;
  f->strm.bz.avail_in = f->bufN == -1 ? 0 : f->bufN;
  f->strm.bz.next_in  = (char *)f->buf;
  return f;
}

static int
cwwrite_bz(struct cfile *f, void *buf, int len)
{
  int n, ret;

  if (len <= 0)
    return len < 0 ? -1 : 0;
  f->strm.bz.avail_in = len;
  f->strm.bz.next_in = buf;
  for (;;)
    {
      f->strm.bz.avail_out = sizeof(f->buf);
      f->strm.bz.next_out = (char *)f->buf;
      ret = BZ2_bzCompress(&f->strm.bz, BZ_RUN);
      if (ret != BZ_RUN_OK)
	return -1;
      n = sizeof(f->buf) - f->strm.bz.avail_out;
      if (n > 0)
	if (cfile_writebuf(f, f->buf, n) != n)
	  return -1;
      if (f->strm.bz.avail_in == 0)
	return len;
    }
}

static int
cwclose_bz(struct cfile *f)
{
  int bytes, ret, n;
  f->strm.bz.avail_in = 0;
  f->strm.bz.next_in = 0;
  for (;;)
    {
      f->strm.bz.avail_out = sizeof(f->buf);
      f->strm.bz.next_out = (char *)f->buf;
      ret = BZ2_bzCompress(&f->strm.bz, BZ_FINISH);
      if (ret != BZ_FINISH_OK && ret != BZ_STREAM_END)
	return -1;
      n = sizeof(f->buf) - f->strm.bz.avail_out;
      if (n > 0)
	if (cfile_writebuf(f, f->buf, n) != n)
	  return -1;
      if (ret == BZ_STREAM_END)
	break;
    }
  BZ2_bzCompressEnd(&f->strm.bz);
  if (f->fd == CFILE_IO_ALLOC)
    cwclose_fixupalloc(f);
  bytes = f->bytes;
  free(f);
  return bytes;
}

static struct cfile *
cwopen_bz(struct cfile *f)
{
  if (!f->level)
    f->level = 9;
  if (BZ2_bzCompressInit(&f->strm.bz, f->level, 0, 30) != BZ_OK)
    {
      free(f);
      return 0;
    }
  return f;
}

static int
crunread_bz(struct cfile *f, void *buf, int len)
{
  return cfile_unreadbuf(f, buf, len, 0);
}


/*****************************************************************
 *  gzip io
 */

static int
crread_gz(struct cfile *f, void *buf, int len)
{
  int ret, used;
  if (f->eof)
    return 0;
  f->strm.gz.avail_out = len;
  f->strm.gz.next_out = buf;
  for (;;)
    {
      if (f->strm.gz.avail_in == 0 && f->bufN)
        {
	  if (cfile_readbuf(f, f->buf, sizeof(f->buf)) == -1)
	    return -1;
          f->strm.gz.avail_in = f->bufN;
          f->strm.gz.next_in = f->buf;
        }
      used = f->strm.gz.avail_in;
      ret = inflate(&f->strm.gz, Z_NO_FLUSH);
      if (ret != Z_OK && ret != Z_STREAM_END)
        return -1;
      used -= f->strm.gz.avail_in;
      if (used && f->ctxup)
	f->ctxup(f->ctx, f->strm.gz.next_in - used, used);
      f->bytes += used;
      if (ret == Z_STREAM_END)
        {
          f->eof = 1;
	  /* read 8 bytes trailer (crc plus len) */
	  if (f->strm.gz.avail_in < 8) {
	    if (f->strm.gz.avail_in && f->ctxup)
	      f->ctxup(f->ctx, f->strm.gz.next_in, f->strm.gz.avail_in);
	    f->bytes += f->strm.gz.avail_in;
	    /* make trailer available in f->buf */
	    if (f->strm.gz.avail_in && f->buf != f->strm.gz.next_in)
	      memmove(f->buf, f->strm.gz.next_in, f->strm.gz.avail_in);
	    used = 8 - f->strm.gz.avail_in;
	    if (cfile_readbuf(f, f->buf + f->strm.gz.avail_in, used) != used)
	      return -1;
	    f->strm.gz.next_in = f->buf + 8;
	    f->strm.gz.avail_in = 0;
	  } else {
	    f->strm.gz.avail_in -= 8;
	    f->strm.gz.next_in += 8;
	    used = 8;
	  }
	  if (f->ctxup)
	    f->ctxup(f->ctx, f->strm.gz.next_in - used, used);
	  /* make trailer available in f->buf */
	  if (f->strm.gz.next_in != f->buf + 8)
	    memmove(f->buf + 8 - used, f->strm.gz.next_in - used, used);
	  f->bytes += used;
          return len - f->strm.gz.avail_out;
        }
      if (f->strm.gz.avail_out == 0)
        return len;
      if (f->bufN == 0)
        return -1;
    }
}

static int
crclose_gz(struct cfile *f)
{
  int r;
  inflateEnd(&f->strm.gz);
  if (f->fd == CFILE_IO_CFILE && f->strm.gz.avail_in)
    {
      struct cfile *cf = (struct cfile *)f->fp;
      if (cf->unread(cf, f->strm.gz.next_in, f->strm.gz.avail_in) != -1)
        f->strm.gz.avail_in = 0;
    }
  if (f->fd == CFILE_IO_PUSHBACK)
    {
      struct cfile *cf = (struct cfile *)f->fp;
      cf->close(cf);
    }
  r = (f->len != CFILE_LEN_UNLIMITED ? f->len : 0) + f->strm.gz.avail_in;
  if (f->unreadbuf != f->buf)
    free(f->unreadbuf);
  free(f);
  return r;
}

static struct cfile *
cropen_gz(struct cfile *f)
{
  int ret, flags;

  if (f->bufN == -1)
    cfile_readbuf(f, f->buf, sizeof(f->buf));
  if (f->bufN < 10)
    {
      free(f);
      return 0;
    }
  flags = f->buf[3];
  if (f->buf[0] != 0x1f || f->buf[1] != 0x8b || f->buf[2] != 8 || (flags & 0xe0) != 0)
    {
      free(f);
      return 0;
    }
  if (f->ctxup)
    f->ctxup(f->ctx, f->buf, 10);
  f->bytes += 10;
  f->strm.gz.avail_in = f->bufN - 10;
  f->strm.gz.next_in = f->buf + 10;
  if (flags)
    {
      int hstate = 1, l = 0;
      if ((flags & 2) != 0)
	flags ^= (32 | 64) ^ 2;		/* skip two bytes */
      if ((flags & 4) != 0)
	flags |= 3;                     /* skip two bytes */
      while (hstate != 64)
	{
	  if ((flags & hstate) == 0)
	    {
	      hstate *= 2;
	      continue;
	    }
	  if (f->strm.gz.avail_in == 0)
	    {
	      if (cfile_readbuf(f, f->buf, sizeof(f->buf)) == -1)
		{
		  free(f);
		  return 0;
		}
	      f->strm.gz.avail_in = f->bufN;
	      f->strm.gz.next_in = f->buf;
	    }
	  if (f->ctxup)
	    f->ctxup(f->ctx, f->strm.gz.next_in, 1);
	  f->bytes++;
	  f->strm.gz.next_in++;
	  f->strm.gz.avail_in--;
	  if (hstate == 1 || hstate == 2 || hstate == 32 || hstate == 64)
	    l = (l >> 8) | ((unsigned char)f->strm.gz.next_in[-1] << 8);
	  else if (hstate == 4 && l-- != 0)
	    continue;
	  else if (f->strm.gz.next_in[-1] != 0)
	    continue;
	  hstate *= 2;
	}
    }
  f->eof = 0;
  f->strm.gz.avail_out = 0;
  f->strm.gz.next_out = 0;
  ret = inflateInit2(&f->strm.gz, -MAX_WBITS);
  if (ret != Z_OK)
    {
      free(f);
      return 0;
    }
  return f;
}

static int
cwwrite_gz(struct cfile *f, void *buf, int len)
{
  int n, ret;

  if (len <= 0)
    return len < 0 ? -1 : 0;
  f->strm.gz.avail_in = len;
  f->strm.gz.next_in = buf;
  for (;;)
    {
      f->strm.gz.avail_out = sizeof(f->buf);
      f->strm.gz.next_out = f->buf;
      ret = deflate(&f->strm.gz, Z_NO_FLUSH);
      if (ret != Z_OK)
	return -1;
      n = sizeof(f->buf) - f->strm.gz.avail_out;
      if (n > 0)
	if (cfile_writebuf(f, f->buf, n) != n)
	  return -1;
      if (f->strm.gz.avail_in == 0)
	{
	  f->crclen += len;
	  f->crc = crc32(f->crc, buf, len);
	  return len;
	}
    }
}

static int
cwclose_gz(struct cfile *f)
{
  int bytes, ret, n;
  for (;;)
    {
      f->strm.gz.avail_out = sizeof(f->buf);
      f->strm.gz.next_out = f->buf;
      ret = deflate(&f->strm.gz, Z_FINISH);
      if (ret != Z_OK && ret != Z_STREAM_END)
	return -1;
      n = sizeof(f->buf) - f->strm.gz.avail_out;
      if (n > 0)
	if (cfile_writebuf(f, f->buf, n) != n)
	  return -1;
      if (ret == Z_STREAM_END)
	break;
    }
  deflateEnd(&f->strm.gz);
  f->buf[0] = f->crc & 0xff;
  f->buf[1] = (f->crc >> 8) & 0xff;
  f->buf[2] = (f->crc >> 16) & 0xff;
  f->buf[3] = (f->crc >> 24) & 0xff;
  f->buf[4] = f->crclen & 0xff;
  f->buf[5] = (f->crclen >> 8) & 0xff;
  f->buf[6] = (f->crclen >> 16) & 0xff;
  f->buf[7] = (f->crclen >> 24) & 0xff;
  if (cfile_writebuf(f, f->buf, 8) != 8)
    return -1;
  if (f->fd == CFILE_IO_ALLOC)
    cwclose_fixupalloc(f);
  bytes = f->bytes;
  free(f);
  return bytes;
}

static struct cfile *
cwopen_gz(struct cfile *f)
{
  int ret;

  f->crc = crc32(0L, Z_NULL, 0);
  f->crclen = 0;
  if (!f->level)
    f->level = Z_BEST_COMPRESSION;
#ifdef Z_RSYNCABLE
  ret = deflateInit2(&f->strm.gz, f->level, Z_DEFLATED, -MAX_WBITS, 8, Z_DEFAULT_STRATEGY | (f->comp == CFILE_COMP_GZ_RSYNC ? Z_RSYNCABLE : 0));
#else
  if (f->comp == CFILE_COMP_GZ_RSYNC)
    ret = Z_VERSION_ERROR;
  else
    ret = deflateInit2(&f->strm.gz, f->level, Z_DEFLATED, -MAX_WBITS, 8, Z_DEFAULT_STRATEGY);
#endif
  if (ret != Z_OK)
    {
      free(f);
      return 0;
    }
  f->strm.gz.avail_in = 0;
  f->strm.gz.next_in  = f->buf;
  f->buf[0] = 0x1f;
  f->buf[1] = 0x8b;
  f->buf[2] = Z_DEFLATED;
  f->buf[3] = 0;
  f->buf[4] = f->buf[5] = f->buf[6] = f->buf[7] = 0;
  f->buf[8] = 0;
  f->buf[9] = 3;	/* OS_UNIX */
  if (cfile_writebuf(f, f->buf, 10) != 10)
    {
      free(f);
      return 0;
    }
  return f;
}


static int
crunread_gz(struct cfile *f, void *buf, int len)
{
  return cfile_unreadbuf(f, buf, len, 0);
}


/*****************************************************************
 *  lzma io
 */

static struct cfile *
cropen_lz(struct cfile *f)
{
  lzma_stream tmp = LZMA_STREAM_INIT;
  f->strm.lz = tmp;
  if (lzma_auto_decoder(&f->strm.lz, 1 << 25, 0) != LZMA_OK)
    {
      free(f);
      return 0;
    }
  f->eof = 0;
  f->strm.lz.avail_in = f->bufN == -1 ? 0 : f->bufN;
  f->strm.lz.next_in  = (unsigned char *)f->buf;
  return f;
}

static int
crread_lz(struct cfile *f, void *buf, int len)
{
  int ret, used;
  if (f->eof)
    return 0;
  f->strm.lz.avail_out = len;
  f->strm.lz.next_out = buf;
  for (;;)
    {
      if (f->strm.lz.avail_in == 0 && f->bufN)
	{
	  if (cfile_readbuf(f, f->buf, sizeof(f->buf)) == -1)
	    return -1;
	  f->strm.lz.avail_in = f->bufN;
	  f->strm.lz.next_in = (unsigned char *)f->buf;
	}
      used = f->strm.lz.avail_in;
      ret = lzma_code(&f->strm.lz, LZMA_RUN);
      if (ret != LZMA_OK && ret != LZMA_STREAM_END)
	return -1;
      used -= f->strm.lz.avail_in;
      if (used && f->ctxup)
	f->ctxup(f->ctx, (unsigned char *)(f->strm.lz.next_in - used), used);
      f->bytes += used;
      if (ret == LZMA_STREAM_END)
	{
	  f->eof = 1;
	  return len - f->strm.lz.avail_out;
	}
      if (f->strm.lz.avail_out == 0)
	return len;
      if (f->bufN == 0)
	return -1;
    }
}

static int
crclose_lz(struct cfile *f)
{
  int r;
  lzma_end(&f->strm.lz);
  if (f->fd == CFILE_IO_CFILE && f->strm.lz.avail_in)
    {
      struct cfile *cf = (struct cfile *)f->fp;
      if (cf->unread(cf, (void *)f->strm.lz.next_in, f->strm.lz.avail_in) != -1)
        f->strm.lz.avail_in = 0;
    }
  r = (f->len != CFILE_LEN_UNLIMITED ? f->len : 0) + f->strm.lz.avail_in;
  if (f->unreadbuf != f->buf)
    free(f->unreadbuf);
  free(f);
  return r;
}

static struct cfile *
cwopen_lz(struct cfile *f)
{
  lzma_options_lzma alone;
  lzma_stream tmp = LZMA_STREAM_INIT;

  if (!f->level)
    f->level = 2;
  f->strm.lz = tmp;
  lzma_lzma_preset(&alone, f->level);
  if (lzma_alone_encoder(&f->strm.lz, &alone) != LZMA_OK)
    {
      free(f);
      return 0;
    }
  return f;
}

static struct cfile *
cwopen_xz(struct cfile *f)
{
  lzma_stream tmp = LZMA_STREAM_INIT;

  if (!f->level)
    f->level = 3;

  f->strm.lz = tmp;
  if (lzma_easy_encoder(&f->strm.lz, f->level, LZMA_CHECK_SHA256) != LZMA_OK)
    {
      free(f);
      return 0;
    }
  return f;
}

static int
cwclose_lz(struct cfile *f)
{
  int bytes, ret, n;
  f->strm.lz.avail_in = 0;
  f->strm.lz.next_in = 0;
  for (;;)
    {
      f->strm.lz.avail_out = sizeof(f->buf);
      f->strm.lz.next_out = (unsigned char *)f->buf;
      ret = lzma_code(&f->strm.lz, LZMA_FINISH);
      if (ret != LZMA_OK && ret != LZMA_STREAM_END)
        return -1;
      n = sizeof(f->buf) - f->strm.lz.avail_out;
      if (n > 0)
        if (cfile_writebuf(f, f->buf, n) != n)
          return -1;
      if (ret == LZMA_STREAM_END)
        break;
    }
  lzma_end(&f->strm.lz);
  if (f->fd == CFILE_IO_ALLOC)
    cwclose_fixupalloc(f);
  bytes = f->bytes;
  free(f);
  return bytes;
}

static int
cwwrite_lz(struct cfile *f, void *buf, int len)
{
  int n, ret;

  if (len <= 0)
    return len < 0 ? -1 : 0;
  f->strm.lz.avail_in = len;
  f->strm.lz.next_in = buf;
  for (;;)
    {
      f->strm.lz.avail_out = sizeof(f->buf);
      f->strm.lz.next_out = (unsigned char *)f->buf;
      ret = lzma_code(&f->strm.lz, LZMA_RUN);
      if (ret != LZMA_OK)
	return -1;
      n = sizeof(f->buf) - f->strm.lz.avail_out;
      if (n > 0)
	if (cfile_writebuf(f, f->buf, n) != n)
	  return -1;
      if (f->strm.lz.avail_in == 0)
	return len;
    }
}

static int
crunread_lz(struct cfile *f, void *buf, int len)
{
  return cfile_unreadbuf(f, buf, len, 0);
}

/*****************************************************************
 *  uncompressed io
 */

static int
crread_un(struct cfile *f, void *buf, int len)
{
  int r;
  r = cfile_readbuf(f, buf, len);
  if (r == -1)
    return -1;
  if (f->ctxup && r)
    f->ctxup(f->ctx, buf, r);
  f->bytes += r;
  return r;
}

static int
crclose_un(struct cfile *f)
{
  int r = f->len != CFILE_LEN_UNLIMITED ? f->len : 0;
  if (f->unreadbuf != f->buf)
    free(f->unreadbuf);
  free(f);
  return r;
}

static struct cfile *
cropen_un(struct cfile *f)
{
  if (f->bufN != -1 && f->bufN != 0)
    {
      /* CFILE_COMP_XX read some bytes, set up unread */
      f->unreadbuf = f->buf;
      f->nunread = f->bufN;
      f->oldread = f->read;
      f->read = crread_ur;
    }
  return f;
}

static int
cwwrite_un(struct cfile *f, void *buf, int len)
{
  return cfile_writebuf(f, buf, len);
}

static int
cwclose_un(struct cfile *f)
{
  int bytes = f->bytes;
  if (f->fd == CFILE_IO_ALLOC)
    cwclose_fixupalloc(f);
  free(f);
  return bytes;
}

static struct cfile *
cwopen_un(struct cfile *f)
{
  return f;
}

static int
crunread_un(struct cfile *f, void *buf, int len)
{
  return cfile_unreadbuf(f, buf, len, 1);
}


#ifdef Z_RSYNCABLE

int
cfile_detect_rsync(struct cfile *f)
{
  unsigned char *b, *b2;
  int i, len, l, eof, p[2];
  int comp = CFILE_COMP_GZ;
  z_stream dstrm, cstrm[2];
  int done, ret, dret;
  unsigned char dbuf[4096], cbuf[4096];

  if (f->comp != CFILE_COMP_GZ)
    return 0;
  b = malloc(4096 + f->strm.gz.avail_in);
  if (!b)
    return -1;
  len = 0;

  p[0] = p[1] = 0;

  dstrm.zalloc = 0;
  dstrm.zfree = 0;
  dstrm.opaque = 0;
  if (inflateInit2(&dstrm, -MAX_WBITS) != Z_OK)
    {
      free(b);
      return -1;
    }
  for (i = 0; i < 2; i++)
    {
      cstrm[i].zalloc = 0;
      cstrm[i].zfree = 0;
      cstrm[i].opaque = 0;
      if (deflateInit2(&cstrm[i], Z_BEST_COMPRESSION, Z_DEFLATED, -MAX_WBITS, 8, Z_DEFAULT_STRATEGY | (i == 1 ? Z_RSYNCABLE : 0)) != Z_OK)
	{
	  if (i)
	    deflateEnd(&cstrm[0]);
	  inflateEnd(&dstrm);
	  free(b);
          return -1;
	}
    }

  done = eof = 0;
  dstrm.avail_in = f->strm.gz.avail_in;
  if (f->strm.gz.avail_in)
    memcpy(b, f->strm.gz.next_in, f->strm.gz.avail_in);
  for (;;)
    {
      if (dstrm.avail_in == 0)
	{
          l = cfile_readbuf(f, b + len, 4096);
	  if (l < 4096)
	    eof = 1;
	}
      else
	l = dstrm.avail_in;
      if (l >= 0)
	{
	  dstrm.avail_in = l;
	  dstrm.next_in = b + len;
	  while (dstrm.avail_in && !done)
	    {
	      dstrm.avail_out = sizeof(dbuf);
	      dstrm.next_out = dbuf;
	      dret = inflate(&dstrm, Z_NO_FLUSH);
	      if (dret != Z_OK && dret != Z_STREAM_END)
		{
		  done = 1;
		  break;
		}
	      if (dstrm.avail_out != sizeof(dbuf))
		{
		  for (i = 0; i < 2 && !done; i++)
		    {
		      cstrm[i].avail_in = sizeof(dbuf) - dstrm.avail_out;
		      cstrm[i].next_in = dbuf;
		      while (cstrm[i].avail_in)
			{
			  cstrm[i].avail_out = sizeof(cbuf);
			  cstrm[i].next_out = cbuf;
			  ret = deflate(&cstrm[i], dret == Z_STREAM_END ? Z_FINISH : Z_NO_FLUSH);
			  if (ret != Z_OK && ret != Z_STREAM_END)
			    {
			      comp = i ? CFILE_COMP_GZ: CFILE_COMP_GZ_RSYNC;
			      done = 1;
			      break;
			    }
			  if (cstrm[i].avail_out != sizeof(cbuf))
			    {
			      if (memcmp(b + p[i], cbuf, sizeof(cbuf) - cstrm[i].avail_out))
				{
				  comp = i ? CFILE_COMP_GZ: CFILE_COMP_GZ_RSYNC;
				  done = 1;
				  break;
				}
			      p[i] += sizeof(cbuf) - cstrm[i].avail_out;
			    }
			  if (cstrm[i].avail_in && ret == BZ_STREAM_END)
			    {
			      comp = i ? CFILE_COMP_GZ: CFILE_COMP_GZ_RSYNC;
			      break;
			    }
			}
		    }
		}
	      if (dret == Z_STREAM_END)
		done = 1;
	    }
	  len += l;
	}
      if (done || eof)
	break;
      b2 = realloc(b, len + 4096);
      if (!b2)
	{
	  comp = -1;
	  break;
	}
      b = b2;
    }
  deflateEnd(&cstrm[0]);
  deflateEnd(&cstrm[1]);
  inflateEnd(&dstrm);
  f->bufN = -1;
  f->strm.gz.avail_in = 0;
  if (comp != -1)
    f->comp = comp;
  if (len)
    {
      struct cfile *cf;
      if (f->fd == CFILE_IO_CFILE || f->fd == CFILE_IO_PUSHBACK)
	{
	  cf = (struct cfile *)f->fp;
	  if (!cf->unread(cf, b, len))
	    {
	      free(b);
	      return -1;
	    }
	  free(b);
	}
      else
	{
	  cf = cfile_open(CFILE_OPEN_RD, f->fd, f->fp, CFILE_COMP_UN, CFILE_LEN_UNLIMITED, 0, 0);
	  if (!cf)
	    {
	      free(b);
	      return -1;
	    }
	  f->fp = cf;
	  f->fd = CFILE_IO_PUSHBACK;
	  cf->unreadbuf = b;
	  cf->nunread = len;
	  cf->oldread = cf->read;
	  cf->read = crread_ur;
	}
      if (f->len != CFILE_LEN_UNLIMITED)
	f->len += len;
    }
  else
    free(b);
  return comp == -1 ? -1 : 0;
}

#else

int
cfile_detect_rsync(struct cfile *f)
{
  return -1;
}

#endif

/*****************************************************************
 *  our open function
 */

struct cfile *
cfile_open(int mode, int fd, void *fp, int comp, size_t len, void (*ctxup)(void *, unsigned char *, unsigned int), void *ctx)
{
  struct cfile *f;
  if (comp == CFILE_COMP_XX && mode == CFILE_OPEN_WR)
    return 0;
  if (mode != CFILE_OPEN_RD && mode != CFILE_OPEN_WR)
    return 0;
  if (fd == CFILE_IO_REOPEN)
    {
      f = fp;
      fd = f->fd;
      fp = f->fp;
    }
  else
    f = malloc(sizeof(*f));
  if (!f)
    return 0;
  f->fd = fd;
  f->fp = fp;
  f->bytes = 0;
  f->len = len;
  f->ctxup = ctxup;
  f->ctx = ctx;
  f->bufN = -1;
  f->nunread = 0;
  f->unreadbuf = 0;
  f->oldread = 0;
  if (mode == CFILE_OPEN_WR && fd == CFILE_IO_ALLOC)
    {
      unsigned char **bp = (unsigned char **)f->fp;
      *bp = 0;
    }
  if (comp == CFILE_COMP_XX)
    {
      comp = CFILE_COMP_UN;
      if (len == CFILE_LEN_UNLIMITED || len >= 2)
	{
	  int n = cfile_readbuf(f, f->buf, sizeof(f->buf));
	  if (n == -1)
	    {
	      free(f);
	      return 0;
	    }
	  if (f->buf[0] == 'B' && f->buf[1] == 'Z')
	    comp = CFILE_COMP_BZ;
	  else if (f->buf[0] == 0x1f && f->buf[1] == 0x8b)
	    comp = CFILE_COMP_GZ;
	  else if (f->buf[0] == 255 && f->buf[1] == 'L' && f->buf[2] == 'Z')
	    comp = CFILE_COMP_LZMA;
	  else if (f->buf[0] == 0135 && f->buf[1] == 0 && f->buf[2] == 0)
	    comp = CFILE_COMP_LZMA;
	  else if (f->buf[0] == 0xfd && f->buf[1] == '7' && f->buf[2] == 'z' && f->buf[3] == 'X' && f->buf[4] == 'Z')
	    comp = CFILE_COMP_XZ;
	}
    }
  f->comp = CFILE_COMPALGO(comp);
  f->level = CFILE_COMPLEVEL(comp);
  switch (f->comp)
    {
    case CFILE_COMP_UN:
      f->read   = mode == CFILE_OPEN_RD ? crread_un : 0;
      f->unread = mode == CFILE_OPEN_RD ? crunread_un : 0;
      f->write  = mode == CFILE_OPEN_WR ? cwwrite_un : 0;
      f->close  = mode == CFILE_OPEN_RD ? crclose_un : cwclose_un;
      return mode == CFILE_OPEN_RD ? cropen_un(f) : cwopen_un(f);
    case CFILE_COMP_GZ:
    case CFILE_COMP_GZ_RSYNC:
      f->strm.gz.zalloc = 0;
      f->strm.gz.zfree = 0;
      f->strm.gz.opaque = 0;
      f->read   = mode == CFILE_OPEN_RD ? crread_gz : 0;
      f->unread = mode == CFILE_OPEN_RD ? crunread_gz : 0;
      f->write  = mode == CFILE_OPEN_WR ? cwwrite_gz : 0;
      f->close  = mode == CFILE_OPEN_RD ? crclose_gz : cwclose_gz;
      return mode == CFILE_OPEN_RD ? cropen_gz(f) : cwopen_gz(f);
    case CFILE_COMP_BZ:
      f->strm.bz.bzalloc = 0;
      f->strm.bz.bzfree = 0;
      f->strm.bz.opaque = 0;
      f->read   = mode == CFILE_OPEN_RD ? crread_bz : 0;
      f->unread = mode == CFILE_OPEN_RD ? crunread_bz : 0;
      f->write  = mode == CFILE_OPEN_WR ? cwwrite_bz : 0;
      f->close  = mode == CFILE_OPEN_RD ? crclose_bz : cwclose_bz;
      return mode == CFILE_OPEN_RD ? cropen_bz(f) : cwopen_bz(f);
    case CFILE_COMP_LZMA:
      f->strm.lz.allocator = 0;
      f->strm.lz.internal = 0;
      f->read   = mode == CFILE_OPEN_RD ? crread_lz : 0;
      f->unread = mode == CFILE_OPEN_RD ? crunread_lz : 0;
      f->write  = mode == CFILE_OPEN_WR ? cwwrite_lz : 0;
      f->close  = mode == CFILE_OPEN_RD ? crclose_lz : cwclose_lz;
      return mode == CFILE_OPEN_RD ? cropen_lz(f) : cwopen_lz(f);
    case CFILE_COMP_XZ:
      f->strm.lz.allocator = 0;
      f->strm.lz.internal = 0;
      f->read   = mode == CFILE_OPEN_RD ? crread_lz : 0;
      f->unread = mode == CFILE_OPEN_RD ? crunread_lz : 0;
      f->write  = mode == CFILE_OPEN_WR ? cwwrite_lz : 0;
      f->close  = mode == CFILE_OPEN_RD ? crclose_lz : cwclose_lz;
      return mode == CFILE_OPEN_RD ? cropen_lz(f) : cwopen_xz(f);
    default:
      free(f);
      return 0;
    }
}

/*****************************************************************
 *  copy data from one cfile to another
 */

int
cfile_copy(struct cfile *in, struct cfile *out, int flags)
{
  unsigned char buf[8192];
  int l, r;
  if (!in || !out)
    return -1;
  while((l = in->read(in, buf, sizeof(buf))) > 0)
    if (out->write(out, buf, l) != l)
      {
	l = -1;
	break;
      }
  if (l != -1)
    l = 0;
  if ((flags & CFILE_COPY_CLOSE_IN))
    {
      if ((r = in->close(in)) != 0)
        if ((flags & CFILE_COPY_CLOSE_OUT) != 0)
	  r = -1;
      if (l != -1)
        l = r;
    }
  if ((flags & CFILE_COPY_CLOSE_OUT))
    {
      r = out->close(out);
      if (l != -1)
	l = r;
    }
  return l;
}

char *
cfile_comp2str(int comp)
{
  if (CFILE_COMPLEVEL(comp))
    {
      static char buf[64];
      sprintf(buf, "%s.%d", cfile_comp2str(CFILE_COMPALGO(comp)), CFILE_COMPLEVEL(comp));
      return buf;
    }
  switch (comp)
    {
    case CFILE_COMP_UN:
      return "uncomp.";
    case CFILE_COMP_GZ:
      return "gzip";
    case CFILE_COMP_GZ_RSYNC:
      return "gzip rsyncable";
    case CFILE_COMP_BZ:
      return "bzip";
    case CFILE_COMP_LZMA:
      return "lzma";
    case CFILE_COMP_XZ:
      return "xz";
    }
  return "???";
}

int
cfile_setlevel(int comp, int level)
{
  int deflevel = 0;
  comp = CFILE_COMPALGO(comp);
  switch(comp)
    {
    case CFILE_COMP_GZ:
    case CFILE_COMP_GZ_RSYNC:
    case CFILE_COMP_BZ:
      deflevel = 9;
      break;
    default:
      break;
    }
  if (level == 0 || level == deflevel)
    return comp;
  return CFILE_MKCOMP(comp, level);
}
