/* ----------------------------------------------------------------------------- 
 * mime.c
 *
 *     This file provides some mimimal MIME handling.
 * 
 * Author(s) : David Beazley (beazley@cs.uchicago.edu)
 *             Mike Sliczniak (mzsliczn@midway.uchicago.edu)
 *
 * Copyright (C) 1999-2000.  The University of Chicago
 * See the file LICENSE for information on usage and redistribution.	
 * ----------------------------------------------------------------------------- */

static char cvsroot[] = "$Header: /cvsroot/swill/SWILL/Source/SWILL/mime.c,v 1.2 2006/12/22 14:37:37 gonzalodiethelm Exp $";

#include "swillint.h"

typedef struct {
   char *suffix;
   char *mimetype;
} MimeType;

static MimeType  types[] = {
   {"txt",  "text/plain"},
   {"htm",  "text/html"},
   {"html", "text/html"},
   {"gif",  "image/gif"},
   {"jpg",  "image/jpg"},
   {"jpeg", "image/jpg"},
   {"rgb",  "image/rgb"},
   {"png",  "image/png"},
   {"pdf",  "application/pdf"},
   { 0, 0},
};

/* -----------------------------------------------------------------------------
 * swill_guess_mimetype(DOH *fn)
 *
 * Give a filename, guess the mimetype based on its suffix
 * ----------------------------------------------------------------------------- */
 
char *
swill_guess_mimetype(const char *filename)
{
   char *cfilename;
   char *c;
   int i;

   cfilename = (char *) DohMalloc(strlen(filename)+1);
   strcpy(cfilename,filename);
   for (c = cfilename; *c; c++) {
      *c = tolower(*c);
   }
   c = cfilename+strlen(cfilename)-1;
   while (c >= cfilename) {
      if (*c == '.') {
	 c++;
	 for (i = 0; types[i].suffix; i++) {
	    if (strcmp(c,types[i].suffix) == 0) {
	       DohFree(cfilename);
	       return types[i].mimetype;
	    }
	 }
	 DohFree(cfilename);
	 return "text/plain";
      }
      c--;
   }
   DohFree(cfilename);
   return "text/plain";
}
