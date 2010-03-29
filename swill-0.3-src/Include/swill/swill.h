/* ----------------------------------------------------------------------------- 
 * swill.h
 *
 *     Header file for the Swill library.
 * 
 * Author(s) : David Beazley (beazley@cs.uchicago.edu)
 *             Mike Sliczniak (mzsliczn@midway.uchicago.edu)
 *
 * Copyright (C) 1999-2000.  The University of Chicago
 * See the file LICENSE for information on usage and redistribution.	
 * ----------------------------------------------------------------------------- */

#ifndef _SWILL_H
#define _SWILL_H

#include <stdio.h>
#include <stdarg.h>

#define SWILL_MAJOR_VERSION 0
#define SWILL_MINOR_VERSION 2


#if defined(WIN32)
#if ! defined(SWILL_DLL)
#define SWILL_DLL 1
#endif
#endif


#if defined(WIN32)
#if defined(SWILL_DLL) && SWILL_DLL > 0
#if defined(SWILL_DLL_BUILDING)
#define SWILL_PUBLIC __declspec(dllexport)
#else
#define SWILL_PUBLIC __declspec(dllimport)
#endif
#else
#define SWILL_PUBLIC
#endif
#else
#define SWILL_PUBLIC
#endif


#define SH(x) (int (*)(FILE *,void *)) x

#if defined(__GNUC__)
#define SWILL_FUNC_FORMAT(archtype,fmt,arg) __attribute__((__format__ (archtype,fmt,arg)))
#else
#define SWILL_FUNC_FORMAT(archtype,fmt,arg)
#endif

#ifdef __cplusplus
extern "C" {
#endif

typedef int   (*SwillHandler)(FILE *, void *);

/*
 * Define a type for a function that gets a password from somewhere.
 */
typedef int swill_ssl_pwd_getter(char* buf, int maxlen);

/* Control functions */

SWILL_PUBLIC int     swill_set_interface(const char* address);
SWILL_PUBLIC int     swill_init_ssl(int port, int ssl, const char* tmpdir);
#define swill_init(port) swill_init_ssl(port, 0, 0)
SWILL_PUBLIC char   *swill_title(const char *title);
SWILL_PUBLIC void    swill_log(FILE *log);
SWILL_PUBLIC int     swill_handle(const char *servname, SwillHandler handler, void *clientdata);
SWILL_PUBLIC int     swill_file(const char *url, const char *filename);
SWILL_PUBLIC void    swill_user(const char *username, const char *password);
SWILL_PUBLIC char   *swill_directory(const char *pathname);
SWILL_PUBLIC int     swill_poll(void);
SWILL_PUBLIC int     swill_serve(void);
SWILL_PUBLIC void    swill_shutdown(void);
#define swill_close swill_shutdown
SWILL_PUBLIC void    swill_remove(const char *servname);
SWILL_PUBLIC void    swill_allow(const char *ip);
SWILL_PUBLIC void    swill_deny(const char *ip);

/* Variable and header functions */
SWILL_PUBLIC char   *swill_getrequest(void);
SWILL_PUBLIC char   *swill_getpeername(void);
SWILL_PUBLIC int     swill_getargs(const char *fmt, ...);
SWILL_PUBLIC char   *swill_getvar(const char *name);
SWILL_PUBLIC int     swill_getint(const char *name);
SWILL_PUBLIC double  swill_getdouble(const char *name);
SWILL_PUBLIC char   *swill_getheader(const char *name);
SWILL_PUBLIC void    swill_setheader(const char *name, const char *value);
SWILL_PUBLIC void    swill_setresponse(const char *value);

/* I/O Functions */

SWILL_PUBLIC int     swill_fprintf(FILE *, const char *fmt, ...) SWILL_FUNC_FORMAT(printf,2,3);
SWILL_PUBLIC int     swill_vfprintf(FILE *f, const char *fmt, va_list ap);
SWILL_PUBLIC int     swill_printf(const char *fmt, ...) SWILL_FUNC_FORMAT(printf,1,2);
SWILL_PUBLIC int     swill_vprintf(const char *fmt, va_list ap);
SWILL_PUBLIC int     swill_logprintf(const char *fmt, ...) SWILL_FUNC_FORMAT(printf,1,2);
SWILL_PUBLIC void    swill_printurl(FILE *f, const char *url, const char *fmt, ...);

SWILL_PUBLIC void    swill_netscape(const char *url);

SWILL_PUBLIC int     swill_ssl_set_certfile(const char* crtfile,
					    const char* keyfile,
					    swill_ssl_pwd_getter pcb);


#ifndef _SWILLINT_H
#define swill_handle(x,y,z) swill_handle(x, SH(y), (void *) z)
#endif

#ifdef __cplusplus
}
#endif
#endif
