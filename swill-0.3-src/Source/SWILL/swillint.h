
#ifndef _SWILLINT_H
#define _SWILLINT_H

#include "swill/swill.h"

#define SWILL_MAX_HEADER 8192
#define SWILL_MAX_QUERY  131072
#define SWILL_TIMEOUT    30
#define SWILL_DEFAULT    "index.html"

#define String DOHString
#define List   DOHList
#define Hash   DOHHash
#define File   DOHFile

#include <fcntl.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <errno.h>
#include <sys/stat.h>
#include <ctype.h>
#include <time.h>
#include <signal.h>

#define assert(x)  if (!(x)) { fprintf(stderr,"%s:%d. Failed assertion." #x "\n", __FILE__, __LINE__); abort(); }


#include "doh.h"

extern int     swill_read_rawrequest(int fd, String **request, String **excess);
extern String *swill_read_post(int fd, int length, String *excess);
extern Hash   *swill_parse_request(String *request);
extern Hash   *swill_parse_request_headers(String *request);
extern int     swill_parse_request_data(Hash *req);

extern Hash   *swill_parse_headers(List *headers);
extern Hash   *swill_parse_query(String *qs);
extern void    swill_url_encode(DOH *in, DOH *out);
extern void    swill_url_decode(DOH *in, DOH *out);
extern void    swill_pre_encode(DOH *in, DOH *out);
extern Hash    *swill_mime_headers(File *in);

extern void    swill_base64_decode(DOH *in, DOH *out);
extern char   *swill_guess_mimetype(const char *fn);
extern DOH    *swill_url_encoder(DOH *);
extern DOH    *swill_pre_encoder(DOH *);

/* Predefined handler functions */
extern Hash *swill_handler_lookup(const String *uri);
extern void  swill_handler_reset(void);
extern int   SwillListHandlers(DOH *out, void *);
extern int   SwillFileNotFound(DOH *out, void *);
extern int   SwillAuthenticate(DOH *out, void *);
extern int   SwillUnsupported(DOH *out, void *);
extern int   SwillFormHandler(DOH *out, void *);

/* Security */
extern int   swill_check_ip(const String *ip);
extern void  swill_security_init();
extern void  swill_security_reset();
extern void  swill_timeout(int seconds);
extern int   swill_checkuser();

extern int   SwillInit;
extern int   SwillTimeout;
extern int   SwillSSL;


#endif





