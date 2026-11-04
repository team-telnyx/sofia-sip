/*
 * This file is part of the Sofia-SIP package
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public License
 * as published by the Free Software Foundation; either version 2.1 of
 * the License, or (at your option) any later version.
 *
 * This library is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA
 * 02110-1301 USA
 *
 */

/**@file test_tport_tls.c
 * @brief Tests for TLS certificate reload (tls_reload_cert()).
 *
 * The TLS implementation is included directly so that the tests can
 * inspect the SSL_CTX held by the master context.
 *
 * Certificates and keys are generated at run time into a temporary
 * directory, so no private keys are kept in the source tree. Each
 * fixture directory holds agent.pem and cafile.pem, as the TLS transport
 * expects:
 *   rotate/, rotate2/  valid certificate and key pairs
 *   mismatch/          certificate with a private key that does not match it
 *   malformed/         certificate file that does not parse
 *   encrypted/         certificate with a key encrypted with "sofia"
 *   dh/                rotate/ with tls-reload/dhparams.pem appended
 */

#include "config.h"

#include "tport_tls.c"

#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <sys/stat.h>

#include <openssl/evp.h>
#include <openssl/x509.h>
#include <openssl/pem.h>

#define TSTFLAGS tstflags
int tstflags;
char const name[] = "test_tport_tls";

#include <sofia-sip/tstdef.h>

static char const *srcdir = ".";
static char fixtures[256];


static char const restricted_ciphers[] = "ECDHE-RSA-AES128-GCM-SHA256";

/* ---------------------------------------------------------------------- */
/* Fixture generation */

static EVP_PKEY *new_key(void)
{
  EVP_PKEY *pkey = NULL;
  EVP_PKEY_CTX *kctx = EVP_PKEY_CTX_new_id(EVP_PKEY_RSA, NULL);

  if (kctx &&
      EVP_PKEY_keygen_init(kctx) > 0 &&
      EVP_PKEY_CTX_set_rsa_keygen_bits(kctx, 2048) > 0)
    EVP_PKEY_keygen(kctx, &pkey);

  EVP_PKEY_CTX_free(kctx);
  return pkey;
}

static X509 *new_cert(EVP_PKEY *pkey, char const *cn)
{
  X509 *x = X509_new();
  X509_NAME *subject;

  if (!x)
    return NULL;

  X509_set_version(x, 2);
  ASN1_INTEGER_set(X509_get_serialNumber(x), 1);
  X509_gmtime_adj(X509_getm_notBefore(x), -3600);
  X509_gmtime_adj(X509_getm_notAfter(x), 3600L * 24 * 365);
  X509_set_pubkey(x, pkey);

  subject = X509_get_subject_name(x);
  X509_NAME_add_entry_by_txt(subject, "O", MBSTRING_ASC,
                             (unsigned char const *)"sofia-sip", -1, -1, 0);
  X509_NAME_add_entry_by_txt(subject, "CN", MBSTRING_ASC,
                             (unsigned char const *)cn, -1, -1, 0);
  X509_set_issuer_name(x, subject);

  if (!X509_sign(x, pkey, EVP_sha256())) {
    X509_free(x);
    return NULL;
  }

  return x;
}

static FILE *open_fixture(char const *dir, char const *file, char const *mode)
{
  char path[512];

  snprintf(path, sizeof path, "%s/%s", fixtures, dir);
  mkdir(path, 0700);
  snprintf(path, sizeof path, "%s/%s/%s", fixtures, dir, file);

  return fopen(path, mode);
}

/* Write agent.pem (cert + key [+ DH params]) and cafile.pem (cert). */
static int write_fixture(char const *dir, X509 *cert, EVP_PKEY *key,
                         char const *passphrase, int with_dh)
{
  FILE *f;
  int ok;

  if (!(f = open_fixture(dir, "agent.pem", "w")))
    return -1;

  ok = PEM_write_X509(f, cert) &&
    (passphrase
     ? PEM_write_PrivateKey(f, key, EVP_aes_128_cbc(), NULL, 0, NULL,
                            (void *)passphrase)
     : PEM_write_PrivateKey(f, key, NULL, NULL, 0, NULL, NULL));

  if (ok && with_dh) {
    char path[512];
    FILE *dh;
    char buf[1024];
    size_t n;

    snprintf(path, sizeof path, "%s/tls-reload/dhparams.pem", srcdir);
    if (!(dh = fopen(path, "r")))
      ok = 0;
    else {
      while ((n = fread(buf, 1, sizeof buf, dh)) > 0)
        fwrite(buf, 1, n, f);
      fclose(dh);
    }
  }

  fclose(f);

  if (!ok || !(f = open_fixture(dir, "cafile.pem", "w")))
    return -1;
  ok = PEM_write_X509(f, cert);
  fclose(f);

  return ok ? 0 : -1;
}

static int make_fixtures(void)
{
  char const *tmp = getenv("TMPDIR");
  EVP_PKEY *k1, *k2, *k3, *k4;
  X509 *c1, *c2, *c3;
  FILE *f;
  int ok;

  snprintf(fixtures, sizeof fixtures, "%s/test_tport_tls.XXXXXX",
           tmp && tmp[0] ? tmp : "/tmp");
  if (!mkdtemp(fixtures))
    return -1;

  k1 = new_key(), k2 = new_key(), k3 = new_key(), k4 = new_key();
  c1 = k1 ? new_cert(k1, "tport reload test") : NULL;
  c2 = k2 ? new_cert(k2, "tport reload test 2") : NULL;
  c3 = k3 ? new_cert(k3, "tport encrypted key test") : NULL;

  ok = k1 && k2 && k3 && k4 && c1 && c2 && c3 &&
    write_fixture("rotate", c1, k1, NULL, 0) == 0 &&
    write_fixture("rotate2", c2, k2, NULL, 0) == 0 &&
    write_fixture("mismatch", c1, k4, NULL, 0) == 0 &&
    write_fixture("encrypted", c3, k3, "sofia", 0) == 0 &&
    write_fixture("dh", c1, k1, NULL, 1) == 0 &&
    write_fixture("malformed", c1, k1, NULL, 0) == 0;

  /* Overwrite malformed/agent.pem with something that does not parse */
  if (ok && (f = open_fixture("malformed", "agent.pem", "w"))) {
    fputs("-----BEGIN CERTIFICATE-----\n"
          "this is not a certificate\n"
          "-----END CERTIFICATE-----\n", f);
    fclose(f);
  }

  X509_free(c1), X509_free(c2), X509_free(c3);
  EVP_PKEY_free(k1), EVP_PKEY_free(k2), EVP_PKEY_free(k3), EVP_PKEY_free(k4);

  return ok ? 0 : -1;
}

static void remove_fixtures(void)
{
  static char const * const dirs[] = {
    "rotate", "rotate2", "mismatch", "malformed", "encrypted", "dh", NULL
  };
  char path[512];
  int i;

  if (!fixtures[0])
    return;

  for (i = 0; dirs[i]; i++) {
    snprintf(path, sizeof path, "%s/%s/agent.pem", fixtures, dirs[i]);
    unlink(path);
    snprintf(path, sizeof path, "%s/%s/cafile.pem", fixtures, dirs[i]);
    unlink(path);
    snprintf(path, sizeof path, "%s/%s", fixtures, dirs[i]);
    rmdir(path);
  }
  rmdir(fixtures);
}

/* ---------------------------------------------------------------------- */

/* Fill the paths the same way tport_reload_tls() does. */
static void issues_for(su_home_t *home, tls_issues_t *ti, char const *dir)
{
  char const *path = su_sprintf(home, "%s/%s", fixtures, dir);

  memset(ti, 0, sizeof *ti);
  ti->key = su_sprintf(home, "%s/agent.pem", path);
  ti->cert = ti->key;
  ti->CAfile = su_sprintf(home, "%s/cafile.pem", path);
  ti->CApath = (char *)path;
  ti->randFile = su_sprintf(home, "%s/tls_seed.dat", path);
  ti->configured = 1;
}

static tls_t *master_for(su_home_t *home, char const *dir,
                         char const *ciphers, char const *passphrase,
                         int enable_dh)
{
  tls_issues_t ti[1];

  issues_for(home, ti, dir);
  ti->ciphers = (char *)ciphers;
  ti->passphrase = (char *)passphrase;
  ti->enable_dh = enable_dh;
  ti->version = TPTLS_VERSION_TLSv1_2;
  ti->timeout = 300;

  return tls_init_master(ti);
}

static int reload(su_home_t *home, tls_t *tls, char const *dir)
{
  tls_issues_t ti[1];

  issues_for(home, ti, dir);

  return tls_reload_cert(tls, ti);
}

static int cipher_count(SSL_CTX *ctx)
{
  STACK_OF(SSL_CIPHER) *ciphers = SSL_CTX_get_ciphers(ctx);
  return ciphers ? sk_SSL_CIPHER_num(ciphers) : -1;
}

static char const *subject_cn(SSL_CTX *ctx, char *buf, int size)
{
  X509 *cert = SSL_CTX_get0_certificate(ctx);

  buf[0] = '\0';
  if (cert)
    X509_NAME_get_text_by_NID(X509_get_subject_name(cert),
                              NID_commonName, buf, size);
  return buf;
}

/* A failed reload must keep the current, working context. */
static int test_reload_failures(void)
{
  su_home_t home[1] = { SU_HOME_INIT(home) };
  tls_t *tls;
  SSL_CTX *ctx;
  char cn[64];

  BEGIN();

  TEST_1(tls = master_for(home, "rotate", NULL, NULL, 0));
  TEST_1(ctx = tls->ctx);
  TEST(SSL_CTX_check_private_key(ctx), 1);

  TEST(reload(home, tls, "mismatch"), -1);
  TEST_P(tls->ctx, ctx);

  TEST(reload(home, tls, "malformed"), -1);
  TEST_P(tls->ctx, ctx);

  TEST(reload(home, tls, "does-not-exist"), -1);
  TEST_P(tls->ctx, ctx);

  /* The kept context still holds the original credentials */
  TEST(SSL_CTX_check_private_key(tls->ctx), 1);
  TEST_S(subject_cn(tls->ctx, cn, sizeof cn), "tport reload test");

  tport_tls_free(tls);
  su_home_deinit(home);

  END();
}

/* A valid reload swaps the context without breaking existing connections. */
static int test_reload_rotation(void)
{
  su_home_t home[1] = { SU_HOME_INIT(home) };
  tls_t *tls;
  SSL_CTX *old_ctx;
  SSL *con;
  char cn[64];

  BEGIN();

  TEST_1(tls = master_for(home, "rotate", NULL, NULL, 0));
  TEST_1(old_ctx = tls->ctx);

  /* A connection created before the reload, as tls_init_secondary() does */
  TEST_1(con = SSL_new(tls->ctx));

  TEST(reload(home, tls, "rotate2"), 0);
  TEST_1(tls->ctx != old_ctx);
  TEST(SSL_CTX_check_private_key(tls->ctx), 1);
  TEST_S(subject_cn(tls->ctx, cn, sizeof cn), "tport reload test 2");

  /* The existing connection keeps its reference to the old context */
  TEST_P(SSL_get_SSL_CTX(con), old_ctx);
  TEST_1(SSL_get_certificate(con) != NULL);
  TEST_S(subject_cn(SSL_get_SSL_CTX(con), cn, sizeof cn), "tport reload test");
  SSL_free(con);

  tport_tls_free(tls);
  su_home_deinit(home);

  END();
}

/* Reload keeps the configured cipher list, passphrase and DH setting. */
static int test_reload_keeps_settings(void)
{
  su_home_t home[1] = { SU_HOME_INIT(home) };
  tls_t *tls, *dflt;
  int n_restricted;
  long options;

  BEGIN();

  /* Restricted cipher list */
  TEST_1(dflt = master_for(home, "rotate", NULL, NULL, 0));
  TEST_1(tls = master_for(home, "rotate", restricted_ciphers, NULL, 0));
  n_restricted = cipher_count(tls->ctx);
  TEST_1(n_restricted > 0);
  TEST_1(n_restricted < cipher_count(dflt->ctx));

  TEST(reload(home, tls, "rotate2"), 0);
  TEST(cipher_count(tls->ctx), n_restricted);

  tport_tls_free(tls);
  tport_tls_free(dflt);

  /* Encrypted private key */
  TEST_1(tls = master_for(home, "encrypted", NULL, "sofia", 0));
  TEST(SSL_CTX_check_private_key(tls->ctx), 1);

  TEST(reload(home, tls, "encrypted"), 0);
  TEST(SSL_CTX_check_private_key(tls->ctx), 1);

  tport_tls_free(tls);

#ifndef OPENSSL_NO_DH
  /* DH parameters, which also set SSL_OP_CIPHER_SERVER_PREFERENCE */
  TEST_1(tls = master_for(home, "dh", NULL, NULL, 1));
  options = SSL_CTX_get_options(tls->ctx);
  TEST_1(options & SSL_OP_CIPHER_SERVER_PREFERENCE);

  TEST(reload(home, tls, "dh"), 0);
  options = SSL_CTX_get_options(tls->ctx);
  TEST_1(options & SSL_OP_CIPHER_SERVER_PREFERENCE);

  tport_tls_free(tls);
#else
  (void)options;
#endif

  su_home_deinit(home);

  END();
}

int main(int argc, char *argv[])
{
  int retval = 0;
  int i;

  for (i = 1; argv[i]; i++) {
    if (strcmp(argv[i], "-v") == 0)
      tstflags |= tst_verbatim;
    else if (strcmp(argv[i], "-a") == 0)
      tstflags |= tst_abort;
    else {
      fprintf(stderr, "usage: %s [-v] [-a]\n", name);
      return 1;
    }
  }

  if (getenv("srcdir"))
    srcdir = getenv("srcdir");

  if (make_fixtures() < 0) {
    fprintf(stderr, "%s: cannot create certificate fixtures\n", name);
    remove_fixtures();
    return 1;
  }

  retval |= test_reload_failures(); fflush(stdout);
  retval |= test_reload_rotation(); fflush(stdout);
  retval |= test_reload_keeps_settings(); fflush(stdout);

  remove_fixtures();

  return retval;
}
