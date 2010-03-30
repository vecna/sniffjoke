/* ----------------------------------------------------------------------------- 
 * ssl.c
 *
 *     SSL related code.
 * 
 * Author(s) : Gonzalo Diethelm (gonzo@diethelm.org)
 *
 * See the file LICENSE for information on usage and redistribution.	
 * ----------------------------------------------------------------------------- */

static char cvsroot[] = "$Header: /cvsroot/swill/SWILL/Source/SWILL/ssl.c,v 1.5 2007/07/10 02:42:43 gonzalodiethelm Exp $";

#include <stdio.h>
#include "swill/swill.h"
#include "ssl.h"

#if ! defined(GONZO_DEBUG)
#define GONZO_DEBUG 0
#endif

#if defined(SWILL_SSL) && (SWILL_SSL > 0)

#include <openssl/ssl.h>
#include <openssl/err.h>

#if defined(WIN32)
#include <openssl/applink.c>
#endif

typedef struct smap
{
   int socket;
   SSL* ssl;
   struct smap* next;
} smap;

static int do_ssl = 0;
static SSL_CTX* ssl_ctx = 0;
static smap* sm = 0;
static swill_ssl_pwd_getter* pem_cb = 0;

static smap* lookup(int sock);
static int do_close(SSL* ssl);
static int pem_password(char* buf,
			int size,
			int rwflag,
			void* password);
static void show_ssl_error(const char* name,
			   SSL* ssl,
			   int ret);

#endif


int swill_ssl_init(int use)
{
#if ! defined(SWILL_SSL) || (SWILL_SSL <= 0)
   swill_ssl_not_supported("swill_ssl_init");
   return -1;
#else
   do_ssl = use;
   if (! do_ssl)
      return 0;

   if (ssl_ctx != 0)
      return 0;

   SSL_load_error_strings();
   SSL_library_init();
   ssl_ctx = SSL_CTX_new(SSLv23_server_method());
   if (ssl_ctx == 0)
   {
      ERR_print_errors_fp(stderr);
      return 0;
   }

   SSL_CTX_set_options(ssl_ctx, SSL_OP_ALL);

#if defined(GONZO_DEBUG) && (GONZO_DEBUG > 0)
   fprintf(stderr, "GONZO: SSL inited at %p\n",
	   ssl_ctx);
#endif

   return 1;
#endif
}

int swill_ssl_term(void)
{
#if ! defined(SWILL_SSL) || (SWILL_SSL <= 0)
   swill_ssl_not_supported("swill_ssl_term");
   return -1;
#else
   smap* x = 0;

   if (! do_ssl)
      return 0;

   if (ssl_ctx == 0)
      return 0;

   for (x = sm; x != 0; ) {
      smap* y = x;
      x = x->next;

      do_close(y->ssl);
      free(y);
   }		

   SSL_CTX_free(ssl_ctx);
   ssl_ctx = 0;

#if defined(GONZO_DEBUG) && (GONZO_DEBUG > 0)
   fprintf(stderr, "GONZO: SSL terminated\n");
#endif

   return 1;
#endif
}

int swill_ssl_set_certfile(const char* crtfile,
			   const char* keyfile,
			   swill_ssl_pwd_getter pcb)
{
#if ! defined(SWILL_SSL) || (SWILL_SSL <= 0)
   swill_ssl_not_supported("swill_ssl_set_certfile");
   return -1;
#else
   if (! do_ssl)
      return 0;

   if (crtfile == 0 || crtfile[0] == '\0' ||
       keyfile == 0 || keyfile[0] == '\0')
      return 0;

   pem_cb = pcb;
   SSL_CTX_set_default_passwd_cb(ssl_ctx, pem_password);

   if (SSL_CTX_use_certificate_file(ssl_ctx, crtfile, SSL_FILETYPE_PEM) != 1 ||
       SSL_CTX_use_PrivateKey_file (ssl_ctx, keyfile, SSL_FILETYPE_PEM) != 1 ||
       SSL_CTX_check_private_key(ssl_ctx ) != 1) {
      ERR_print_errors_fp(stderr);
      return 0;
   }

#if defined(GONZO_DEBUG) && (GONZO_DEBUG > 0)
   fprintf(stderr, "GONZO: SSL using cert file [%s/%s]\n",
	   crtfile, keyfile);
#endif

   return 1;
#endif
}

int swill_ssl_accept(int sock)
{
#if ! defined(SWILL_SSL) || (SWILL_SSL <= 0)
   swill_ssl_not_supported("swill_ssl_accept");
   return -1;
#else
   smap* x = 0;
   int n = 0;

   if (! do_ssl)
      return 0;

   x = lookup(sock);
   if (x->ssl != 0)
      return 1;

   x->ssl = SSL_new(ssl_ctx);
   if (x->ssl == 0) {
      ERR_print_errors_fp(stderr);
      return 0;
   }

   if (SSL_set_fd(x->ssl, sock) != 1) {
      ERR_print_errors_fp(stderr);
      return 0;
   }

   n = SSL_accept(x->ssl);
   if (n != 1) {
      show_ssl_error("SSL_accept", x->ssl, n);
      return 0;
   }

#if defined(GONZO_DEBUG) && (GONZO_DEBUG > 0)
   fprintf(stderr, "GONZO: SSL issued accept on socket %d: %p\n",
	   sock, x->ssl);
#endif

   return 1;
#endif
}

int swill_ssl_close(int sock)
{
#if ! defined(SWILL_SSL) || (SWILL_SSL <= 0)
   swill_ssl_not_supported("swill_ssl_close");
   return -1;
#else
   smap* x = 0;

   if (! do_ssl)
      return 0;

   x = lookup(sock);
   do_close(x->ssl);
   x->ssl = 0;

#if defined(GONZO_DEBUG) && (GONZO_DEBUG > 0)
   fprintf(stderr, "GONZO: SSL issued close on socket %d\n",
	   sock);
#endif

   return 1;
#endif
}

int swill_ssl_read(int sock, char* buf, int size)
{
#if ! defined(SWILL_SSL) || (SWILL_SSL <= 0)
   swill_ssl_not_supported("swill_ssl_read");
   return -1;
#else
   smap* x = 0;
   int n = 0;

   if (! do_ssl)
      return 0;

   x = lookup(sock);
   if (x->ssl == 0)
      return 0;

   n = SSL_read(x->ssl, buf, size);
   if (n < 0) {
      show_ssl_error("SSL_read", x->ssl, n);
      return 0;
   }

#if defined(GONZO_DEBUG) && (GONZO_DEBUG > 0)
   fprintf(stderr, "GONZO: SSL issued read on socket %d, %d bytes\n",
	   sock, n);
#endif

   return n;

#endif
}

int swill_ssl_write(int sock, char* buf, int size)
{
#if ! defined(SWILL_SSL) || (SWILL_SSL <= 0)
   swill_ssl_not_supported("swill_ssl_write");
   return -1;
#else
   smap* x = 0;
   int n = 0;

   if (! do_ssl)
      return 0;

   x = lookup(sock);
   if (x->ssl == 0)
      return 0;

   n = SSL_write(x->ssl, buf, size);
   if (n < 0) {
      show_ssl_error("SSL_write", x->ssl, n);
      return 0;
   }

#if defined(GONZO_DEBUG) && (GONZO_DEBUG > 0)
   fprintf(stderr, "GONZO: SSL issued write on socket %d, %d bytes\n",
	   sock, n);
#endif

   return n;
#endif
}

void swill_ssl_not_supported(const char* name)
{
   fprintf(stderr, "SSL function [%s] not supported\n", name);
}


#if defined(SWILL_SSL) && (SWILL_SSL > 0)

static smap* lookup(int sock)
{
   smap* x;

   for (x = sm; x != 0; x = x->next)
      if (x->socket == sock)
	 break;

   if (x == 0) {
      x = (smap*) malloc(sizeof(smap));
      x->socket = sock;
      x->ssl = 0;
      x->next = sm;
      sm = x;
   }

   return x;
}

static int do_close(SSL* ssl)
{
   if (ssl != 0)
      SSL_free(ssl);

   return 1;
}

static int pem_password(char* buf,
			int size,
			int rwflag,
			void* password)
{
#define MAX_PWD 256
   char tmp[MAX_PWD];

   if (pem_cb == 0)
      strcpy(tmp, "*UNKNOWN*");
   else
      pem_cb(tmp, MAX_PWD);

   strncpy(buf, tmp, size);
   return strlen(buf);
}

static void show_ssl_error(const char* name,
			   SSL* ssl,
			   int ret)
{
   int err = SSL_get_error(ssl, ret);
   fprintf(stderr, "%s returned %d, error %d, errno %d, errors:\n",
	   name, ret, err, errno);
   ERR_print_errors_fp(stderr);
}

#endif
