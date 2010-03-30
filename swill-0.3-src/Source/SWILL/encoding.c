/* ----------------------------------------------------------------------------- 
 * encoding.c
 *
 *     This file implements a number of filters for encoding and decoding data
 *     in various formats including URL encoding and Base 64.
 * 
 * Author(s) : David Beazley (beazley@cs.uchicago.edu)
 *             Mike Sliczniak (mzsliczn@midway.uchicago.edu)
 *
 * Copyright (C) 1999-2000.  The University of Chicago
 * See the file LICENSE for information on usage and redistribution.	
 * ----------------------------------------------------------------------------- */

static char cvsroot[] = "$Header: /cvsroot/swill/SWILL/Source/SWILL/encoding.c,v 1.3 2006/12/22 14:37:37 gonzalodiethelm Exp $";

#include "swillint.h"

/* -----------------------------------------------------------------------------
 * swill_url_decode()
 *
 * Decodes a url-encoded string.  '+' characters are converted into spaces
 * and '%xx' sequences are converted into their character equivalent.
 *
 *     in    Is any file-like object supporting a Getc method.
 *     out   Is any file-like object supporting a Putc method.
 *
 * ----------------------------------------------------------------------------- */

void 
swill_url_decode(DOH *in, DOH *out) {
   int  ch, nch;
   int  i;
   while (1) {
      ch = Getc(in);
      if (ch == EOF) return;
      if (ch == '+') {
	 Putc(' ',out);
      } else {
	 if (ch == '%') {
	    nch = 0;
	    for (i = 0; i < 2; i++) {
	       nch = nch << 4;
	       ch = Getc(in);
	       if (ch == EOF) {
		  Putc(ch,out);
		  return;
	       } 
	       if (isxdigit(ch)) {
		  if (isdigit(ch)) {
		     nch += (ch - '0');
		  } else {
		     nch += (tolower(ch) - 'a') + 10;
		  }
	       }
	    }
	    Putc(nch,out);
	 } else {
	    Putc(ch,out);
	 }
      }
   }
}

/* -----------------------------------------------------------------------------
 * swill_url_encode()
 *
 * Encodes a string. Spaces are converted into '+' and all other non-valid
 * characters are converted into a '%xx' sequence.
 * ----------------------------------------------------------------------------- */

void 
swill_url_encode(DOH *in, DOH *out) {
   int  ch;
   char *trans = "0123456789abcdef";
   while (1) {
      ch = Getc(in);
      if (ch == EOF) return;
      if (ch == ' ') {
	 Putc('+',out);
      } else if (isalnum(ch) || (ch == '_')) {
	 Putc(ch,out);
      } else {
	 int i;
	 Putc('%',out);
	 i = (ch & 0xf0) >> 4;
	 Putc(trans[i],out);
	 i = (ch & 0x0f);
	 Putc(trans[i],out);
      }
   }
}

/* ----------------------------------------------------------------------------- 
 * swill_url_encoder()
 *
 * Function given to DohEncoder for printf conversions.
 * ----------------------------------------------------------------------------- */

DOH *
swill_url_encoder(DOH *s) {
   DOH *ns = NewString("");
   swill_url_encode(s,ns);
   return ns;
}

/* -----------------------------------------------------------------------------
 * swill_pre_encode()
 *
 * Take a piece of text and perform a few character substitutions for HTML.
 * ----------------------------------------------------------------------------- */

void 
swill_pre_encode(DOH *in, DOH *out) {
   int ch;
   while (1) {
      ch = Getc(in);
      if (ch == EOF) return;
      else if (ch == '<') Write(out,"&lt;",4);
      else if (ch == '>') Write(out,"&gt;",4);
      else if (ch == '&') Write(out,"&amp;",5);
      else Putc(ch,out);
   }
}

/* -----------------------------------------------------------------------------
 * swill_pre_encoder()
 *
 * Encoder function registered with Printf
 * ----------------------------------------------------------------------------- */
 
DOH *
swill_pre_encoder(DOH *s) {
   DOH *ns = NewString("");
   int ch;
   while (1) {
      ch = Getc(s);
      if (ch == EOF) return ns;
      else if (ch == '<') Write(ns,"&lt;",4);
      else if (ch == '>') Write(ns,"&gt;",4);
      else if (ch == '&') Write(ns,"&amp;",5);
      else Putc(ch,ns);
   }
}

/* -----------------------------------------------------------------------------
 * Base64 decoding
 * ----------------------------------------------------------------------------- */

static char *base64chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/=";
static unsigned char base64map[256];
static int  base64init = 0;

static void init_base64() {
   unsigned int i;
   for (i = 0; i < 256; i++) {
      base64map[i] = 255;
   }
   for (i = 0; i < strlen(base64chars); i++) {
      base64map[base64chars[i]] = i;
   }
   
}

/* -----------------------------------------------------------------------------
 * swill_base64_decode()
 * 
 * Decode a base64 encoded data stream.
 *
 *   in   - Any file-like object with a Getc method.  The base64 input stream.
 *   out  - Any file-like object with a Putc method.  The base64 output stream.
 *
 * This function is primarily used to decode passwords.
 * ----------------------------------------------------------------------------- */

void
swill_base64_decode(DOH *in, DOH *out) {
   char group[4];
   int grpi;
   int i,ch;
   int nbytes;
   if (!base64init) {
      init_base64();
      base64init = 1;
   }
   while (1) {
      /* Read in a triplet */
      for (i = 0; i < 4; i++) {
	l1:
	 ch = Getc(in);
	 if (ch == EOF) break;
	 if (base64map[ch] == 255) goto l1;
	 group[i] = ch;
      } 
      /* Pad out to a multiple of four */
      while (i < 4) {
	 group[i] = '=';
	 i++;
      }
      /* Figure out how many bytes are to be read */
      nbytes = 3;
      for (i = 4; i > 0; i--) {
	 if (group[i-1] != '=') break;
	 nbytes--;
      }

      /* Decode the string */
      grpi = 0;
      for (i = 0; i < 4; i++) {
	 grpi = grpi << 6;
	 grpi = grpi + ((base64map[group[i]]) & 63);
      }
    
      if (nbytes >= 1) {
	 Putc((grpi >> 16) & 0xff, out);
      }
      if (nbytes >= 2) {
	 Putc((grpi >> 8) & 0xff, out);
      }
      if (nbytes >= 3) {
	 Putc(grpi & 0xff, out);
      }
      if ((ch == EOF) || (nbytes < 3)) return;
   }
}
