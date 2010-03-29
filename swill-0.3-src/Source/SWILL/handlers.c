/* ----------------------------------------------------------------------------- 
 * handlers.c
 *
 *     Functions for registering SWIG handler functions.   Also includes
 *     default handlers for various error conditions.
 * 
 * Author(s) : David Beazley (beazley@cs.uchicago.edu)
 *             Mike Sliczniak (mzsliczn@midway.uchicago.edu)
 *
 * Copyright (C) 1999-2000.  The University of Chicago
 * See the file LICENSE for information on usage and redistribution.	
 * ----------------------------------------------------------------------------- */

static char cvsroot[] = "$Header: /cvsroot/swill/SWILL/Source/SWILL/handlers.c,v 1.3 2008/02/26 21:32:17 gonzalodiethelm Exp $";

#include "swillint.h"
#include <stdarg.h>

static Hash *Handlers = 0;

/* -----------------------------------------------------------------------------
 * int swill_handle()
 *
 * Register a handler function with the server
 * 
 *      servname   =  Document name used by the server (i.e., "foo.html")
 *      handler    =  Handler function
 *      clientdata =  Data passed to the handler function
 *
 * Note: MIME type is guessed from the servname suffix.
 *
 * The servname may include options before the actual name.  For example:
 * "stdout:foo.html" indicates that output is going to use standard output
 * ----------------------------------------------------------------------------- */

int
swill_handle(const char *servname, SwillHandler handler, void *clientdata) {
   Hash  *handobj;
   const char  *actname;
   char  opt[512] = { 0 };

   if (!Handlers) {
      Handlers = NewHash();
   }
   /* Check for options */
   actname = strchr(servname,':');
   if (actname) {
      strncat(opt,servname,actname - servname);
      actname++;
   } else {
      actname = servname;
   }
   handobj = NewHash();
   if (*actname == '/') actname++;
   Setattr(handobj,"servname",actname);
   Setattr(handobj,"handler",NewVoid((void*)handler,0));
   Setattr(handobj,"clientdata",NewVoid(clientdata,0));
   Setattr(handobj,"mimetype", swill_guess_mimetype(servname));
  
   if (strcmp(opt,"stdout") == 0) {
      SetInt(handobj,"stdout",1);
   }
   Setattr(Handlers,actname,handobj);
   return 0;
}

/* -----------------------------------------------------------------------------
 * swill_file()
 *
 * Serve a registered filename
 * ----------------------------------------------------------------------------- */

int 
swill_file(const char *url, const char *path)
{
   Hash *handobj;
   if (!Handlers) {
      Handlers = NewHash();
   }
   handobj = NewHash();
   Setattr(handobj,"servname",url);
   if (path) {
      Setattr(handobj,"filename",path);
   } else {
      Setattr(handobj,"filename",url);
   }
   Setattr(handobj,"mimetype",swill_guess_mimetype(url));
   Setattr(Handlers,url,handobj);
   return 0;
}

/* -----------------------------------------------------------------------------
 * swill_remove()
 * 
 * Remove a handler
 * ----------------------------------------------------------------------------- */

void 
swill_remove(const char *name) {
   if (!Handlers) return;
   Delattr(Handlers,name);
}

/* -----------------------------------------------------------------------------
 * swill_handler_reset()
 * 
 * Reset all of the handlers
 * ----------------------------------------------------------------------------- */

void
swill_handler_reset(void) {
   Delete(Handlers);
   Handlers = 0;
}

/* -----------------------------------------------------------------------------
 * swill_handler_lookup()
 *
 * Look up a handler given a URI
 * ----------------------------------------------------------------------------- */

Hash *
swill_handler_lookup(const String *uri) {
   if (!Handlers) return 0;
   return Getattr(Handlers,uri);
}

/* -----------------------------------------------------------------------------
 * SwillFileNotFound()
 *
 * Report a file not found error to the client.
 * ----------------------------------------------------------------------------- */

static char *error404msg =
"\n"
"<html><head><title>File not found</title></head>\n"
"<body bgcolor=\"#ffffff\">\n"
"<h1>File not found</h1>\n"
"Document '%s' not registered with the server.\n"
#if defined(SWILL_IGNORE_INFO) && (SWILL_IGNORE_INFO > 0)
#else
"Click <a href=\"/info\">here</a> for a list of available documents.\n\n"
#endif
"</body></html>\n";

int 
SwillFileNotFound(DOH *out, void *clientdata) {
   swill_setresponse("404 File not found");
   swill_setheader("Content-Type","text/html");
   Printf(out,error404msg,swill_getvar("__uri__"));
   return 0;
}

/* -----------------------------------------------------------------------------
 * SwillAuthenticate()
 *
 * Ask the user to authenticate themselves with a username and password.
 * ----------------------------------------------------------------------------- */

static char *error401msg = "\n\
<html><head><title>Unauthorized</title></head>\n\
<body bgcolor=\"#ffffff\">\n\
<h1>Unauthorized</h1>\n\
You don't have access to this document. Sorry.\n\
</body></html>\n";

int 
SwillAuthenticate(DOH *out, void *clientdata) {
   swill_setresponse("401 Unauthorized");
   swill_setheader("Content-Type","text/html");
   Printf(out,error401msg);
   return 0;
}

/* -----------------------------------------------------------------------------
 * SwillUnsupported()
 *
 * Unsupported HTTP method
 * ----------------------------------------------------------------------------- */

static char *error501msg = "\n\
<html><head><title>Not implemented</title></head>\n\
<body bgcolor=\"#ffffff\">\n\
<h1>Not implemented</h1>\n\
The server does not support '%s' requests.\n\
</body></html>\n";

int 
SwillUnsupported(DOH *out, void *clientdata) {
   swill_setresponse("501 Not Implemented");
   swill_setheader("Content-Type","text/html");
   Printf(out,error501msg,swill_getvar("__method__"));
   return 0;
}

/* -----------------------------------------------------------------------------
 * SwillInternalError()
 *
 * Internal server error.
 * ----------------------------------------------------------------------------- */

static char *error500msg = "\n\
<html><head><title>Internal Error</title></head>\n\
<body bgcolor=\"#ffffff\">\n\
<h1>Internal Error</h1>\n\
</plaintext>\n";

int 
SwillInternalError(DOH *out, void *clientdata) {
   swill_setresponse("500 Internal Error");
   swill_setheader("Content-Type","text/html");
   Printf(out,error500msg);
   return 0;
}

/* -----------------------------------------------------------------------------
 * SwillListHandlers()
 *
 * Print a list of all available handlers.
 * ----------------------------------------------------------------------------- */

int 
SwillListHandlers(DOH *out, void *clientdata) {
   DOH *namelist, *key, *item;
   int i;

   swill_setheader("Content-Type","text/html");
   Printf(out,"<html><head><title>%s</title></head>\n", swill_title(0));
   Printf(out,"<body bgcolor=\"#ffffff\">\n");
   Printf(out,"<h1>%s</h1>\n", swill_title(0));
   Printf(out,"<b>Registered Handlers</b>\n");
   Printf(out,"<ul>\n");
   namelist = NewList();
   for (key = Firstkey(Handlers); key; key = Nextkey(Handlers)) {
      Append(namelist,key);
   }
   /*  List_sort(namelist); */
   for (i = 0; i < Len(namelist); i++ ) {
      item = Getattr(Handlers,Getitem(namelist,i));
      Printf(out,"<li> <a href=\"%s\">%s</a>\n", Getattr(item,"servname"),Getattr(item,"servname"));
   }
   if (Len(namelist) == 0) {
      Printf(out,"<li> None\n");
   }
   Printf(out,"</ul>\n");

   /*
     if (swill_->docroot) {
     Printf(out,"<p><b>Document Root</b>\n");
     Printf(out,"<ul>\n");
     Printf(out,"<li><a href=\"/\">%s</a>\n", swill_w->docroot);
     Printf(out,"</ul>\n");
     }
   */

   Printf(out,"<hr>\n");
   Printf(out,"<em>SWILL %d.%d</em>\n", SWILL_MAJOR_VERSION, SWILL_MINOR_VERSION);
   Delete(namelist);
   return 0;
}

/* -----------------------------------------------------------------------------
 * swill_getvars()
 *
 * A high level function for grabbing form variables.   The user supplies a 
 * format string that specifies names and conversions.  For example:
 *
 *    swill_getvars("s(name)s(email)d(number)", &name, &email, &number)
 *
 * Returns 0 on failure.  1 on success.  
 * ----------------------------------------------------------------------------- */

static const char *isolate_name(const char *c, char *t) {
   int copy = 0;
   while (*c) {
      if (*c == '(') {
	 copy = 1;
	 c++;
	 continue;
      }
      if (*c == ')') {
	 *t = 0;
	 return c;
      }
      if (copy) {
	 *(t++) = *c;
      }
      c++;
   }
   *t = 0;
   return c - 1;
}

int 
swill_getargs(const char *fmt, ...) {
   const char *c;
   char name[256];
   va_list ap;
   int opt = 0;
   int code = 0;
   char *value = 0;
   void *ptr = 0;

   va_start(ap,fmt);
   c = fmt;

   /* Walk the fmt string and get arguments */
   while (*c) {
      if (*c == '|') {
	 opt = 1;
	 c++;
	 continue;
      }
      code = *c;
      ptr = va_arg(ap, void *);
      c = isolate_name(c,name);
      value = swill_getvar(name);
      if (!value) {
	 if (!opt) {   /* Not optional.  Error */
	    va_end(ap);
	    return 0;
	 }
	 c++;
	 continue;
      }
      switch(code) {
	 case 's':         /* String */
	    *((char **) ptr) = value;
	    break;
      
	 case 'i':         /* Integer */
	    *((int *) ptr) = (int) strtol(value,NULL,0);
	    break;
      
	 case 'l':         /* Long */
	    *((long *) ptr) = atol(value);
	    break;

	 case 'h':         /* Short */
	    *((short *) ptr) = (short) strtol(value,NULL,0);
	    break;

	 case 'b':         /* Byte */
	    *((char *) ptr) = (char) strtol(value,NULL,0);
	    break;

	 case 'I':         /* unsigned integer */
	    *((unsigned int *) ptr) = (unsigned int) strtoul(value, NULL, 0);
	    break;
      
	 case 'L':         /* unsigned long */
	    *((unsigned long *) ptr) = (unsigned long) strtoul(value, NULL, 0);
	    break;

	 case 'H':         /* unsigned short */
	    *((unsigned short *) ptr) = (unsigned short) strtoul(value,NULL,0);
	    break;

	 case 'B':         /* unsigned byte */
	    *((unsigned char *) ptr) = (unsigned char) strtoul(value,NULL,0);
	    break;

	 case 'f':         /* Float */
	    *((float *) ptr) = (float) atof(value);
	    break;

	 case 'd':         /* Double */
	    *((double *) ptr) = atof(value);
	    break;

	 case 'p':
	    *((void **) ptr) = (void *) strtoul(value, NULL, 0);
	    break;

	 default:
	    break;
      }
      c++;
   }
   va_end(ap);
   return 1;
}

void
swill_printurl(FILE *f, const char *url, const char *fmt, ...) {
   const char *c;
   char name[256];
   va_list ap;
   int code = 0;
   char   *svalue;
   int     ivalue;
   unsigned int uivalue;
   long    lvalue;
   unsigned long ulvalue;
   double  dvalue;
   void *ptr = 0;
   int     first = 1;

   va_start(ap,fmt);
  
   fprintf(f,"%s",url);

   c = fmt;
   if (*c) {
      fprintf(f,"?");
   }
   /* Walk the fmt string and get arguments */
   while (*c) {
      code = *c;
      c = isolate_name(c,name);
      if (!first) {
	 swill_fprintf(f,"&");
      }
      first = 0;
      switch(code) {
	 case 's':         /* String */
	    svalue = va_arg(ap, char *);
	    swill_fprintf(f,"%s=%(url)s", name, svalue);
	    break;
      
	 case 'i':         /* Integer */
	 case 'h':
	 case 'b':
	    ivalue = va_arg(ap, int);
	    swill_fprintf(f,"%s=%(url)d", name, ivalue);
	    break;
      
	 case 'l':         /* Long */
	    lvalue = va_arg(ap, long);
	    swill_fprintf(f,"%s=%(url)ld", name, lvalue);
	    break;

	 case 'I':         /* unsigned integer */
	 case 'H':
	 case 'B':
	    uivalue = va_arg(ap, unsigned);
	    swill_fprintf(f,"%s=%(url)u", name, uivalue);
	    break;
      
	 case 'L':         /* unsigned long */
	    ulvalue = va_arg(ap, unsigned long);
	    swill_fprintf(f,"%s=%(url)ul", name, ulvalue);
	    break;

	 case 'f':         /* Float */
	 case 'd':
	    dvalue = va_arg(ap, double);
	    swill_fprintf(f,"%s=%(url)0.17f", name, dvalue);
	    break;

	 case 'p':
	    ptr = va_arg(ap, void *);
	    swill_fprintf(f,"%s=%(url)p", name, ptr);
	    break;

	 default:
	    break;
      }
      c++;
   }
   va_end(ap);
   return;
}




