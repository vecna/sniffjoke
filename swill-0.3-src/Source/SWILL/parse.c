/* ----------------------------------------------------------------------------- 
 * parse.c
 *
 *     This file contains code to parse HTTP requests into various subcomponents
 * 
 * Author(s) : David Beazley (beazley@cs.uchicago.edu)
 *             Mike Sliczniak (mzsliczn@midway.uchicago.edu)
 *
 * Copyright (C) 1999-2000.  The University of Chicago
 * See the file LICENSE for information on usage and redistribution.	
 * ----------------------------------------------------------------------------- */

static char cvsroot[] = "$Header: /cvsroot/swill/SWILL/Source/SWILL/parse.c,v 1.5 2006/12/22 14:37:37 gonzalodiethelm Exp $";

#include "swillint.h"
#include "sock.h"

/* -----------------------------------------------------------------------------
 * swill_read_rawrequest()
 *
 * Reads a raw HTTP request from a file descriptor.  This function is responsible
 * for reading directly from the underlying socket.  It is very picky and only 
 * allows headers smaller than SWILL_MAX_HEADER.
 *
 * Returns 0 on error.  Otherwise, it returns 1 and places the request in the
 * passed request string.  excess is a string containing excess data that was
 * supplied on the connection, but which is not part of the request header.
 * ----------------------------------------------------------------------------- */

int 
swill_read_rawrequest(int fd, String **request, String **excess)
{
   char   buffer[SWILL_MAX_HEADER];
   char   requestbuf[SWILL_MAX_HEADER];
   int    buf_in = 0;
   int    request_in = 0;
   int    state = 0;
   int    len;
   char   c;

   while (buf_in < SWILL_MAX_HEADER) {
      if (! swill_sock_can_read(fd, SwillTimeout)) {
	 /* Timeout.  We're gone */
	 swill_logprintf("Request read timeout! ");
	 return 0;
      }

      len = swill_sock_do_read(fd, buffer+buf_in, SWILL_MAX_HEADER-buf_in);

      if (len < 0)
	 return 0;       /* Read error. Failure!! */

      if (len == 0)
	 continue;

      while (len > 0) {
	 c = buffer[buf_in];
	 if (c == '\r') {         /* Nuke carriage returns (A Windows bogosity) */
	    buf_in++;
	    len--;
	    continue;
	 }
	 switch (state) {
	    case 0:	/* Request line */
	       requestbuf[request_in++] = c;
	       if (c == '\n') {
		  state = 1;
	       } 
	       break;
	    case 1:  /* End of headers? */
	       if (c == '\n') {
		  *request = NewString("");
		  Write(*request,requestbuf,request_in);    /* Save request                          */
		  *excess = NewString("");
		  Write(*excess,buffer+buf_in, len);        /* Write remaining data in excess string */
		  return 1;
	       } else {
		  requestbuf[request_in++] = c;
		  state = 0;
	       }
	       break;
	 }
	 len--;
	 buf_in++;
      }
   }
   /* Header is too large. Bail out with an error */
   return 0;
}

/* -----------------------------------------------------------------------------
 * swill_read_post()
 *
 * Reads data supplied with a POST operation.   Returns as a string on success.
 * Returns NULL on failure.
 * ----------------------------------------------------------------------------- */

String *
swill_read_post(int fd, int length, String *excess)
{
   char buffer[8192];
   int  rlen;
   int  elen;
   String *post;

   if (length > SWILL_MAX_QUERY) {
      return 0;
   }

   post = NewString("");
   /* First copy data in the excess string over */
   elen = Len(excess);
   if (length < elen) elen = length;
   Write(post,Char(excess),elen);
   length -= elen;
  
   while (length > 0) {
      if (! swill_sock_can_read(fd, SwillTimeout)) {
	 /* Timeout.  We're gone */
	 Delete(post);
	 return 0;
      }

      rlen = swill_sock_do_read(fd, buffer, 8192);

      if (rlen < 0) {
	 Delete(post);
	 return 0;       /* Read error. Failure!! */
      }

      if (rlen == 0)
	 continue;

      Write(post,buffer,rlen);
      length -= rlen;
   }
   return post;
}

/* -----------------------------------------------------------------------------
 * swill_parse_url()
 *
 * Parses the request line of a HTTP header, splitting it into an operation,
 * URI, and query string.  Returns 1 on success, 0 otherwise.
 * ----------------------------------------------------------------------------- */

int
swill_parse_url(String *request, String **op_out, String **url_out, String **query_out) {
   List *fields;
   String *rawurl;
   List   *urlparts;

   fields = Split(request," ", -1);
   if (Len(fields) != 3) {
      Delete(fields);
      return 0;
   }
   *op_out = Copy(Getitem(fields,0));
   rawurl = Getitem(fields,1);
   Delitem(rawurl,0);            /* Nuke first character */
   urlparts = Split(rawurl,"?",1);
  
   *url_out = Copy(Getitem(urlparts,0));
   if (Len(urlparts) > 1) {
      *query_out = Copy(Getitem(urlparts,1));
   } else {
      *query_out = 0;
   }
  
   Delete(urlparts);
   Delete(fields);
   return 1;
}

/* -----------------------------------------------------------------------------
 * swill_parse_query()
 *
 * Parse a query string into a hash-table of attribute-value pairs
 * ----------------------------------------------------------------------------- */

Hash *
swill_parse_query(String *qs) {
   List *list;
   Hash *map;
   int i;
   map = NewHash();

   if (!qs) return map;
   list = Split(qs,"&",-1);             /* Split into fields */
   for (i = 0; i < Len(list); i++) {
      String *item, *name, *value, *decoded;
      List   *pair;
      item = Getitem(list,i);
      pair = Split(item,"=",1);
      if (Len(pair) != 2) {
	 Delete(pair);
	 Delete(list);
	 Delete(map);
	 return 0;
      }
      name = Getitem(pair,0);
      value = Getitem(pair,1);
      if (name && value) {
	 decoded = NewString("");
	 Seek(value,0,SEEK_SET);
	 swill_url_decode(value,decoded);
	 Setattr(map,name,decoded);
	 Delete(decoded);
      }
      Delete(pair);
   }
   Delete(list);
   return map;
}


/* -----------------------------------------------------------------------------
 * convert_tolower()
 *
 * Convert a string to all lower-case.  Used in HTTP header parsing.
 * ----------------------------------------------------------------------------- */

static String *
convert_tolower(String *in) {
   String *str;
   int  ch;
   str = NewString("");
   Seek(in,0,SEEK_SET);
   while (1) {
      ch = Getc(in);
      if (ch != EOF) {
	 Putc(tolower(ch),str);
      } else {
	 break;
      }
   }
   return str;
}

/* -----------------------------------------------------------------------------
 * swill_parse_headers()
 *
 * Parse a list of RFC822 lines into a hash table
 * ----------------------------------------------------------------------------- */

Hash *
swill_parse_headers(List *lines) {
   /* Grab all of the HTTP headers and put into a hash object */
   Hash *headers;
   String *header;
   List   *pair;
   String *name, *value = 0;
   int i;
   headers = NewHash();
   for (i = 0; i < Len(lines); i++) {
      header = Getitem(lines,i);
      if (!Len(header)) return headers;     /* Blank line.  End of headers */
      if (isspace(*(Char(header)))) {
	 /* Must be a continuation */
	 if (value)
	    Append(value,header);
	 continue;
      }
      pair = Split(header,":",1);       /* Split into components */
      if (Len(pair) == 2) {
	 String *nlower;
	 name = Getitem(pair,0);
	 value = Getitem(pair,1);
	 Delitem(value,0);              /* Get rid of leading space */
	 nlower = convert_tolower(name);
	 Setattr(headers,nlower,value);
	 Delete(nlower);
      }
      Delete(pair);
   }
   return headers;
}

/* -----------------------------------------------------------------------------
 * swill_parse_request_headers()
 *
 * Takes a request string and parses it into a full request object.  Returns a 
 * hash table that contains the following fields:
 *
 *       uri         - HTTP URI
 *       method      - HTTP Method
 *       query       - Hash table of query variables
 *       headers     - Hash table of HTTP headers
 *       request     - Raw request string that can be used to regenerate the request
 *       querystring - Raw query string
 *
 * Returns 0 on failure.
 * ----------------------------------------------------------------------------- */

Hash *
swill_parse_request_headers(String *request) {
   List *lines;
   String *urlline;
   String *method = 0, *uri = 0, *querystring = 0;
   Hash   *headers = 0;

   Hash *reqh = NewHash();
  
   /* Split request into lines */
   lines = Split(request,"\n",-1);
   if (Len(lines) < 1) {
      Delete(reqh);
      Delete(lines);
      return 0;
   }
   urlline = Getitem(lines,0);

   if (!swill_parse_url(urlline, &method, &uri, &querystring)) {
      /* Bad HTTP request */
      Delete(reqh);
      Delete(lines);
      return 0;
   }
   Delitem(lines,0);
   headers = swill_parse_headers(lines);
   if (!headers) {
      Delete(reqh);
      Delete(lines);
      Delete(method);
      Delete(uri);
      Delete(querystring);
      return 0;
   }
  
   /* If the uri has zero length, then we use the SWILL default document.
      Usually this is "index.html" */
  
   if ((Len(uri) == 0)) {
      Append(uri, SWILL_DEFAULT);
   }

   /* Request looks okay for now */
   Setattr(reqh,"uri", uri);
   Setattr(reqh,"method",method);
   Setattr(reqh,"headers", headers);
   Setattr(reqh,"request", request);
   Setattr(reqh,"querystring", querystring);

   Delete(lines);
   Delete(headers);
   Delete(uri);
   Delete(method);
   Delete(querystring);
   return reqh;
} 

/* -----------------------------------------------------------------------------
 * swill_parse_request_data()
 *
 * Takes a hash returned by swill_parse_request_headers and parses form variables
 * ----------------------------------------------------------------------------- */

int
swill_parse_request_data(Hash *reqh) {

   String *method;
   String *qs = 0;
   Hash   *headers;
   Hash   *query;
   int     post = 0;

   method = Getattr(reqh,"method");
   if (!method) return 0;

   headers = Getattr(reqh,"headers");
   if (!headers) return 0;

   if (Strcmp(method,"GET") == 0) {
      qs = Getattr(reqh,"querystring");
   } else if (Strcmp(method,"POST") == 0) {
      /* Data follows the headers */
      String *req = Getattr(reqh,"request");
      int length = GetInt(headers,"content-length");
      if (length > 0) {
	 /* Find start of the headers */
	 char *qsc = Strstr(req,"\n\n");
	 if (qsc) qs = NewString(qsc+2);
	 Chop(qs);
      }
      post = 1;
   }
   if (qs) {
      query = swill_parse_query(qs);
      if (post) {
	 Setattr(reqh,"querystring",qs);
	 Delete(qs);
      }
      if (!query) {
	 return 0;
      }
      Setattr(reqh,"query",query);
      Delete(query);
   } else {
      query = NewHash();
      Setattr(reqh,"query", query);
      Delete(query);
   }
   /* Set up some additional query variables */
   Setattr(query,"__uri__", Getattr(reqh,"uri"));
   Setattr(query,"__method__",method);
   return 1;
}

/* -----------------------------------------------------------------------------
 * swill_parse_request()
 *
 * Parses a complete request in a string
 * ----------------------------------------------------------------------------- */

Hash *
swill_parse_request(String *request) {
   Hash *h = swill_parse_request_headers(request);
   if (!h) return 0;

   if (!(swill_parse_request_data(h))) {
      Delete(h);
      return 0;
   }
   return h;
}


