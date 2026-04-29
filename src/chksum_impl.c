/*
 * Copyright (c) 2026, SUSE LLC
 *
 * This program is licensed under the BSD license, read LICENSE.BSD
 * for further information
 */

#include <sys/types.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "pool.h"
#include "util.h"
#include "chksum.h"

#include "md5.h"
#include "sha1.h"
#include "sha2.h"

/* keep in sync with chksum.c */
struct s_Chksum {
  Id type;
  void *(*impl)(struct s_Chksum *, int op);
  unsigned char result[SOLV_CHKSUM_MAXLEN];
  union {
    MD5_CTX md5;
    SHA1_CTX sha1;
    SHA224_CTX sha224;
    SHA256_CTX sha256;
    SHA384_CTX sha384;
    SHA512_CTX sha512;
  } c;
};

static void *
solv_chksum_impl(Chksum *chk, int op)
{
  if (op == SOLV_CHKSUMP_IMPL_CLONE)
    return solv_memdup(chk, sizeof(*chk));
  else if (op != SOLV_CHKSUMP_IMPL_FINALIZE)
    return 0;
  switch(chk->type)
    {
    case REPOKEY_TYPE_MD5:
      solv_MD5_Final(chk->result, &chk->c.md5);
      chk->impl = 0;
      return chk->result + 16;
    case REPOKEY_TYPE_SHA1:
      solv_SHA1_Final(&chk->c.sha1, chk->result);
      chk->impl = 0;
      return chk->result + 20;
    case REPOKEY_TYPE_SHA224:
      solv_SHA224_Final(chk->result, &chk->c.sha224);
      chk->impl = 0;
      return chk->result + 28;
    case REPOKEY_TYPE_SHA256:
      solv_SHA256_Final(chk->result, &chk->c.sha256);
      chk->impl = 0;
      return chk->result + 32;
    case REPOKEY_TYPE_SHA384:
      solv_SHA384_Final(chk->result, &chk->c.sha384);
      chk->impl = 0;
      return chk->result + 48;
    case REPOKEY_TYPE_SHA512:
      solv_SHA512_Final(chk->result, &chk->c.sha512);
      chk->impl = 0;
      return chk->result + 64;
    default:
      break;
    }
  return 0;
}

Chksum *
solv_chksum_create(Id type)
{
  Chksum *chk;
  chk = solv_calloc(1, sizeof(*chk));
  chk->type = type;
  chk->impl = solv_chksum_impl;
  switch(type)
    {
    case REPOKEY_TYPE_MD5:
      solv_MD5_Init(&chk->c.md5);
      return chk;
    case REPOKEY_TYPE_SHA1:
      solv_SHA1_Init(&chk->c.sha1);
      return chk;
    case REPOKEY_TYPE_SHA224:
      solv_SHA224_Init(&chk->c.sha224);
      return chk;
    case REPOKEY_TYPE_SHA256:
      solv_SHA256_Init(&chk->c.sha256);
      return chk;
    case REPOKEY_TYPE_SHA384:
      solv_SHA384_Init(&chk->c.sha384);
      return chk;
    case REPOKEY_TYPE_SHA512:
      solv_SHA512_Init(&chk->c.sha512);
      return chk;
    default:
      break;
    }
  free(chk);
  return 0;
}

void
solv_chksum_add(Chksum *chk, const void *data, int len)
{
  if (!chk->impl)
    return;
  switch(chk->type)
    {
    case REPOKEY_TYPE_MD5:
      solv_MD5_Update(&chk->c.md5, (void *)data, len);
      return;
    case REPOKEY_TYPE_SHA1:
      solv_SHA1_Update(&chk->c.sha1, data, len);
      return;
    case REPOKEY_TYPE_SHA224:
      solv_SHA224_Update(&chk->c.sha224, data, len);
      return;
    case REPOKEY_TYPE_SHA256:
      solv_SHA256_Update(&chk->c.sha256, data, len);
      return;
    case REPOKEY_TYPE_SHA384:
      solv_SHA384_Update(&chk->c.sha384, data, len);
      return;
    case REPOKEY_TYPE_SHA512:
      solv_SHA512_Update(&chk->c.sha512, data, len);
      return;
    default:
      break;
    }
}

