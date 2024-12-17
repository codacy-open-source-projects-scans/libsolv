/*
 * Copyright (c) 2024, SUSE LLC
 *
 * This program is licensed under the BSD license, read LICENSE.BSD
 * for further information
 */

#include <sys/types.h>
#include <sys/stat.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <fcntl.h>

#include <zlib.h>


#include "pool.h"
#include "repo.h"
#include "util.h"
#include "chksum.h"
#include "solv_xfopen.h"
#include "tarhead.h"
#include "repo_apk.h"


struct zstream {
  int fd;
  int eof;
  z_stream zs;
  unsigned char buf[65536];
  void (*readcb)(void *, const void *, int);
  void *readcb_data;
};

static struct zstream *
apkz_open(int fd)
{
  struct zstream *zstream = solv_calloc(1, sizeof(*zstream));
  zstream->fd = fd;
  if (inflateInit2(&zstream->zs, 15 + 32) != Z_OK)	/* 32: enable gzip */
    {
      solv_free(&zstream->zs);
      return 0;
    }
  return zstream;
}

static int
apkz_close(void *cookie)
{
  struct zstream *zstream = cookie;
  inflateEnd(&zstream->zs);
  if (zstream->fd != -1)
    close(zstream->fd);
  solv_free(zstream);
  return 0;
}

static ssize_t
apkz_read(void *cookie, char *buf, size_t len)
{
  struct zstream *zstream = cookie;
  int r, eof = 0;
  ssize_t old_avail_in;

  if (!zstream)
    return -1;
  if (zstream->eof)
    return 0;
  zstream->zs.avail_out = len;
  zstream->zs.next_out = (unsigned char *)buf;
  for (;;)
    {
      if (zstream->zs.avail_in == 0)
	{
	  ssize_t rr = read(zstream->fd, zstream->buf, sizeof(zstream->buf));
	  if (rr < 0)
	    return rr;
	  if (rr == 0)
	      eof = 1;
	  zstream->zs.avail_in = rr;
	  zstream->zs.next_in = zstream->buf;
	}
      old_avail_in = zstream->zs.avail_in;
      r = inflate(&zstream->zs, Z_NO_FLUSH);

      if ((r == Z_OK || r == Z_STREAM_END) && zstream->readcb)
	if (zstream->zs.avail_in < old_avail_in)
	  {
	    int l = old_avail_in - zstream->zs.avail_in;
	    zstream->readcb(zstream->readcb_data, (const void *)(zstream->zs.next_in - l), l);
	  }

      if (r == Z_STREAM_END)
	{
	  zstream->eof = 1;
	  return len - zstream->zs.avail_out;
	}
      if (r != Z_OK)
	return -1;
      if (zstream->zs.avail_out == 0)
	return len;
      if (eof)
	return -1;
    }
}

static int
apkz_reset(struct zstream *zstream)
{
  zstream->eof = 0;
  if (zstream->zs.avail_in == 0)
    {
      ssize_t rr = read(zstream->fd, zstream->buf, sizeof(zstream->buf));
      if (rr <= 0)
	return rr < 0 ? -1 : 0;
      zstream->zs.avail_in = rr;
      zstream->zs.next_in = zstream->buf;
    }
  inflateReset(&zstream->zs);
  return 1;
}

static void
add_deps(Repo *repo, Solvable *s, Id what, char *p)
{
  Pool *pool = repo->pool;
  Id oldwhat = what;
  Id supplements = 0;
  while (*p)
    {
      char *pn, *pv;
      int flags = 0;
      Id id;
      while (*p == ' ' || *p == '\t')
	p++;
      what = oldwhat;
      if (what == SOLVABLE_REQUIRES && *p == '!')
	{
	  what = SOLVABLE_CONFLICTS;
	  p++;
	}
      pn = p;
      while (*p && *p != ' ' && *p != '\t' && *p != '<' && *p != '>' && *p != '=' && *p != '~')
	p++;
      id =  pool_strn2id(pool, pn, p - pn, 1);
      for (; *p; p++)
	{
	  if (*p == '<')
	    flags |= REL_LT;
	  else if (*p == '>')
	    flags |= REL_GT;
	  else if (*p == '=')
	    flags |= REL_EQ;
	  else
	    break;
	}
      if (*p == '~')
	flags |= REL_EQ;
      if (flags)
	{
	  pv = p;
	  while (*p && *p != ' ' && *p != '\t')
	    p++;
	  id = pool_rel2id(pool, id, pool_strn2id(pool, pv, p - pv, 1), flags, 1);
	}
      if (what == SOLVABLE_PROVIDES)
        s->provides = repo_addid_dep(repo, s->provides, id, 0);
      else if (what == SOLVABLE_REQUIRES)
        s->requires = repo_addid_dep(repo, s->requires, id, 0);
      else if (what == SOLVABLE_CONFLICTS)
        s->conflicts = repo_addid_dep(repo, s->conflicts, id, 0);
      else if (what == SOLVABLE_SUPPLEMENTS)
	supplements = supplements ? pool_rel2id(pool, id, supplements, REL_AND, 1) : id;
    }
  if (supplements)
    s->supplements = repo_addid_dep(repo, s->supplements, supplements, 0);
}

Id
repo_add_apk_pkg(Repo *repo, const char *fn, int flags)
{
  Pool *pool = repo->pool;
  Repodata *data;
  int fd;
  FILE *fp;
  struct zstream *zstream;
  struct tarhead th;
  Solvable *s = 0;
  Chksum *pkgidchk = 0;
  Chksum *q1chk = 0;
  char *line = 0;
  size_t l, line_alloc = 0;
  int haveorigin = 0;

  data = repo_add_repodata(repo, flags);
  if ((fd = open(flags & REPO_USE_ROOTDIR ? pool_prepend_rootdir_tmp(pool, fn) : fn, O_RDONLY)) == -1)
    {
      pool_error(pool, -1, "%s: %s", fn, strerror(errno));
      return 0;
    }
  zstream = apkz_open(fd);
  if (!zstream)
    {
      pool_error(pool, -1, "%s: %s", fn, strerror(errno));
      close(fd);
      return 0;
    }
  if ((fp = solv_cookieopen(zstream, "r", apkz_read, 0, apkz_close)) == 0) {
    pool_error(pool, -1, "%s: %s", fn, strerror(errno));
    apkz_close(zstream);
    return 0;
  }

  /* skip signatures */
  while (getc(fp) != EOF)
    ;
  if (apkz_reset(zstream) != 1)
    {
      pool_error(pool, -1, "%s: unexpected EOF", fn);
      fclose(fp);
      return 0;
    }
  if (flags & APK_ADD_WITH_HDRID)
    {
      q1chk = solv_chksum_create(REPOKEY_TYPE_SHA1);
      zstream->readcb_data = q1chk;
      zstream->readcb = (void *)solv_chksum_add;
    }
  clearerr(fp);
  tarhead_init(&th, fp);
  while (tarhead_next(&th) > 0)
    {
      if (th.type != 1 || strcmp(th.path, ".PKGINFO") != 0 || s)
	{
	  tarhead_skip(&th);
	  continue;
	}
      if (th.length > 10 * 1024 * 1024)
	{
	  pool_error(pool, -1, "%s: oversized .PKGINFO", fn);
	  break;
	}
      s = pool_id2solvable(pool, repo_add_solvable(repo));
      if (flags & APK_ADD_WITH_PKGID)
        pkgidchk = solv_chksum_create(REPOKEY_TYPE_MD5);
      while ((l = tarhead_gets(&th, &line, &line_alloc)) > 0)
	{
	  if (pkgidchk)
	    solv_chksum_add(pkgidchk, line, l);
	  l = strlen(line);
	  if (l && line[l - 1] == '\n')
	    line[--l] = 0;
	  if (l == 0 || line[0] == '#')
	    continue;
	  if (!strncmp(line, "pkgname = ", 10))
	    s->name = pool_str2id(pool, line + 10, 1);
	  else if (!strncmp(line, "pkgver = ", 9))
	    s->evr = pool_str2id(pool, line + 9, 1);
	  else if (!strncmp(line, "pkgdesc = ", 10))
	    {
	      repodata_set_str(data, s - pool->solvables, SOLVABLE_SUMMARY, line + 10);
	      repodata_set_str(data, s - pool->solvables, SOLVABLE_DESCRIPTION, line + 10);
	    }
	  else if (!strncmp(line, "url = ", 6))
	    repodata_set_str(data, s - pool->solvables, SOLVABLE_URL, line + 6);
	  else if (!strncmp(line, "builddate = ", 12))
	    repodata_set_num(data, s - pool->solvables, SOLVABLE_BUILDTIME, strtoull(line + 12, 0, 10));
	  else if (!strncmp(line, "packager = ", 11))
	    repodata_set_poolstr(data, s - pool->solvables, SOLVABLE_PACKAGER, line + 11);
	  else if (!strncmp(line, "size = ", 7))
	    repodata_set_num(data, s - pool->solvables, SOLVABLE_INSTALLSIZE, strtoull(line + 7, 0, 10));
	  else if (!strncmp(line, "arch = ", 7))
	    s->arch = pool_str2id(pool, line + 7, 1);
	  else if (!strncmp(line, "license = ", 10))
	    repodata_add_poolstr_array(data, s - pool->solvables, SOLVABLE_LICENSE, line + 10);
	  else if (!strncmp(line, "origin = ", 9))
	    {
	      if (s->name && !strcmp(line + 9,  pool_id2str(pool, s->name)))
	        repodata_set_void(data, s - pool->solvables, SOLVABLE_SOURCENAME);
	      else
		repodata_set_id(data, s - pool->solvables, SOLVABLE_SOURCENAME, pool_str2id(pool, line + 9, 1));
	      haveorigin = 1;
	    }
	  else if (!strncmp(line, "depend = ", 9))
	    add_deps(repo, s, SOLVABLE_REQUIRES, line + 9);
	  else if (!strncmp(line, "provides = ", 11))
	    add_deps(repo, s, SOLVABLE_PROVIDES, line + 11);
	  else if (!strncmp(line, "install_if = ", 13))
	    add_deps(repo, s, SOLVABLE_SUPPLEMENTS, line + 13);
	}
    }
  solv_free(line);
  tarhead_free(&th);
  fclose(fp);
  if (s && !s->name)
    {
      pool_error(pool, -1, "%s: package has no name", fn);
      s = solvable_free(s, 1);
    }
  if (s)
    {
      if (!s->arch)
	s->arch = ARCH_NOARCH;
      if (!s->evr)
	s->evr = ID_EMPTY;
      if (s->name)
	s->provides = repo_addid_dep(repo, s->provides, pool_rel2id(pool, s->name, s->evr, REL_EQ, 1), 0);
      if (s->name && !haveorigin)
	repodata_set_void(data, s - pool->solvables, SOLVABLE_SOURCENAME);
      if (pkgidchk)
	{
	  unsigned char pkgid[16];
	  solv_chksum_free(pkgidchk, pkgid);
	  repodata_set_bin_checksum(data, s - pool->solvables, SOLVABLE_PKGID, REPOKEY_TYPE_MD5, pkgid);
	  pkgidchk = 0;
	}
      if (q1chk)
	{
	  unsigned char hdrid[20];
	  solv_chksum_free(q1chk, hdrid);
	  repodata_set_bin_checksum(data, s - pool->solvables, SOLVABLE_HDRID, REPOKEY_TYPE_SHA1, hdrid);
	  q1chk = 0;
	}
      if (!(flags & REPO_NO_LOCATION))
	repodata_set_location(data, s - pool->solvables, 0, 0, fn);
    }
  if (q1chk)
    solv_chksum_free(q1chk, 0);
  if (pkgidchk)
    solv_chksum_free(pkgidchk, 0);
  if (!(flags & REPO_NO_INTERNALIZE))
    repodata_internalize(data);
  return s ? s - pool->solvables : 0;
}

static void
apk_add_hdrid(Repodata *data, Id p, char *idstr)
{
  size_t l = strlen(idstr);
  unsigned char chksum[33], *cp = chksum;

  if (((l == 30 || l == 46) && idstr[0] == 'Q' && idstr[1] == '1') || (idstr[1] == '2' && l == 46))
    {
      int xpos = idstr[1] == '2' ? 43 : 27;
      int i, v;

      l -= 2;
      idstr += 2;
      for (i = v = 0; i < l; i++)
	{
	  int x = idstr[i];
	  if (x >= 'A' && x <= 'Z')
	    x -= 'A';
	  else if (x >= 'a' && x <= 'z') 
	    x -= 'a' - 26;
	  else if (x >= '0' && x <= '9') 
	    x -= '0' - 52;
	  else if (x == '+') 
	    x = 62;
	  else if (x == '/') 
	    x = 63;
	  else if (x == '=' && i == xpos) 
	    x = 0;
	  else
	    return;
	  v = v << 6 | x;
	  if ((i & 3) == 3)
	    {
	      *cp++ = v >> 16;
	      *cp++ = v >> 8;
	      if (i != xpos)
		  *cp++ = v;
	      v = 0;
	    }
	}
      repodata_set_bin_checksum(data, p, SOLVABLE_HDRID, l == 28 ? REPOKEY_TYPE_SHA1 : REPOKEY_TYPE_SHA256, chksum);
    }
}

static void
apk_process_index(Repo *repo, Repodata *data, struct tarhead *th)
{
  Pool *pool = repo->pool;
  Solvable *s = 0;
  char *line = 0;
  size_t l, line_alloc = 0;
  int haveorigin = 0;

  for (;;)
    {
      l = tarhead_gets(th, &line, &line_alloc);
      if (s && (l == 0 || (l == 1 && line[0] == '\n')))
	{
	  /* finish old solvable */
	  if (!s->name)
	    repo_free_solvable(repo, s - pool->solvables, 1);
	  else
	    {
	      if (!s->arch)
		s->arch = ARCH_NOARCH;
	      if (!s->evr)
		s->evr = ID_EMPTY;
	      if (s->name)
		s->provides = repo_addid_dep(repo, s->provides, pool_rel2id(pool, s->name, s->evr, REL_EQ, 1), 0);
	      if (s->name && !haveorigin)
		repodata_set_void(data, s - pool->solvables, SOLVABLE_SOURCENAME);
	    }
	  s = 0;
	}

      if (l == 0)
	break;

      l = strlen(line);
      if (l && line[l - 1] == '\n')
	line[--l] = 0;
      if (l < 2 || line[1] != ':')
	continue;
      if (!s)
	{
	  s = pool_id2solvable(pool, repo_add_solvable(repo));
	  haveorigin = 0;
	}
      if (line[0] == 'P')
	s->name = pool_str2id(pool, line + 2, 1);
      else if (line[0] == 'V')
	s->evr = pool_str2id(pool, line + 2, 1);
      else if (line[0] == 'T')
	{
	  repodata_set_str(data, s - pool->solvables, SOLVABLE_SUMMARY, line + 2);
	  repodata_set_str(data, s - pool->solvables, SOLVABLE_DESCRIPTION, line + 2);
	}
      else if (line[0] == 'U')
	repodata_set_str(data, s - pool->solvables, SOLVABLE_URL, line + 2);
      else if (line[0] == 't')
	repodata_set_num(data, s - pool->solvables, SOLVABLE_BUILDTIME, strtoull(line + 2, 0, 10));
      else if (line[0] == 'I')
	repodata_set_num(data, s - pool->solvables, SOLVABLE_INSTALLSIZE, strtoull(line + 2, 0, 10));
      else if (line[0] == 'A')
	s->arch = pool_str2id(pool, line + 2, 1);
      else if (line[0] == 'L')
	repodata_add_poolstr_array(data, s - pool->solvables, SOLVABLE_LICENSE, line + 2);
      else if (line[0] == 'o')
	{
	  if (s->name && !strcmp(line + 2,  pool_id2str(pool, s->name)))
	    repodata_set_void(data, s - pool->solvables, SOLVABLE_SOURCENAME);
	  else
	    repodata_set_id(data, s - pool->solvables, SOLVABLE_SOURCENAME, pool_str2id(pool, line + 2, 1));
	  haveorigin = 1;
	}
      else if (line[0] == 'D')
	add_deps(repo, s, SOLVABLE_REQUIRES, line + 2);
      else if (line[0] == 'p')
	add_deps(repo, s, SOLVABLE_PROVIDES, line + 2);
      else if (line[0] == 'i')
	add_deps(repo, s, SOLVABLE_SUPPLEMENTS, line + 2);
      else if (line[0] == 'C')
	apk_add_hdrid(data, s - pool->solvables, line + 2);
    }
  solv_free(line);
}

Id
repo_add_apk_repo(Repo *repo, FILE *fp, int flags)
{
  struct tarhead th;
  Repodata *data;

  data = repo_add_repodata(repo, flags);

  tarhead_init(&th, fp);
  if ((flags & APK_ADD_INDEX) != 0)
    apk_process_index(repo, data, &th);
  else
    {
      while (tarhead_next(&th) > 0)
	{
	  if (th.type != 1 || strcmp(th.path, "APKINDEX") != 0)
	    tarhead_skip(&th);
	  else
	    apk_process_index(repo, data, &th);
	}
    }
  tarhead_free(&th);
  return 0;
}

