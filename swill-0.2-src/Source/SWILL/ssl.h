/* ----------------------------------------------------------------------------- 
 * ssl.h
 *
 *     Header file for the SSL related code.
 * 
 * Author(s) : Gonzalo Diethelm (gonzo@diethelm.org)
 *
 * See the file LICENSE for information on usage and redistribution.	
 * ----------------------------------------------------------------------------- */

#ifndef _SSL_H
#define _SSL_H

#if defined(SWILL_SSL) && (SWILL_SSL > 0)

int swill_ssl_init(int use);
int swill_ssl_term(void);
int swill_ssl_accept(int sock);
int swill_ssl_close(int sock);
int swill_ssl_read(int sock, char* buf, int size);
int swill_ssl_write(int sock, char* buf, int size);

#else

void swill_ssl_not_supported(const char* name);

#endif

#endif
