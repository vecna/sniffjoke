/* -----------------------------------------------------------------------------
 * io.c
 *
 * SWILL I/O wrapper library.
 *
 * Author(s) : David Beazley (beazley@cs.uchicago.edu)
 * ----------------------------------------------------------------------------- */

#include "swillint.h"
#include <stdarg.h>
#include <string.h>

/* 
 * These are the C library functions that SWILL likes to intercept.
 * First, we define them as functions named swill_* so that they
 * are accessible by their longer names.   Then we will define
 * replacements for the standard C functions.
 */

int swill_vfprintf(FILE *f, const char *fmt, va_list arg) {
   return DohvPrintf(f,fmt,arg);
}

int swill_fprintf(FILE *f, const char *fmt, ...) {
   va_list ap;
   int ret = 0;
   va_start(ap,fmt);
   ret = swill_vfprintf(f,fmt,ap);
   va_end(ap);
   return ret;
}

int swill_vprintf(const char *fmt, va_list arg) {
   return DohvPrintf(stdout,fmt,arg);
}

int swill_printf(const char *fmt, ...) {
   va_list ap;
   int ret = 0;
   va_start(ap,fmt);
   ret = swill_vprintf(fmt,ap);
   va_end(ap);
   return ret;
}


