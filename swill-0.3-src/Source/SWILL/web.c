/* ----------------------------------------------------------------------------- 
 * web.c
 *
 *     This file implements the web-server.
 * 
 * Author(s) : David Beazley (beazley@cs.uchicago.edu)
 *             Sotiria Lampoudi (slampoud@cs.uchicago.edu)
 *             Mike Sliczniak (mzsliczn@midway.uchicago.edu)
 *
 * Copyright (C) 1999-2000.  The University of Chicago
 * See the file LICENSE for information on usage and redistribution.	
 * ----------------------------------------------------------------------------- */

static char cvsroot[] = "$Header: /cvsroot/swill/SWILL/Source/SWILL/web.c,v 1.18 2008/02/26 21:32:18 gonzalodiethelm Exp $";

#if ! defined(GONZO_DEBUG)
#define GONZO_DEBUG 0
#endif

#if defined(WIN32)

#include <IO.h>
#include <Windows.h>

#define lstat(n,b) stat(n,b)
#define ftruncate(d,s) chsize(d,s)
#define S_ISDIR(m) (m & _S_IFDIR)

#endif


#include "swillint.h"
#include "sock.h"
#include "ssl.h"

/* 
   #define __USE_MPI
   #undef __USE_MPI
*/

#ifdef __USE_MPI 
#include <mpi.h>
#endif

/* Server info */

int     SwillInit    = 0;
int     SwillSSL     = 0;
static int     SwillSocket  = -1;
static int     SwillPort    = 0;
static String *SwillTitle   = 0;
static String *SwillDocroot = 0;
int     SwillTimeout = SWILL_TIMEOUT;

static char    SwillFName[512];
static FILE   *SwillFile    = 0;

#ifdef __USE_MPI
static int _swill_mpi_rank, _swill_mpi_numprocs;
#endif

/* Global variables containing information about the current request */
static Hash   *http_out_headers = 0;
static String *http_uri         = 0;
static String *http_response    = 0;
static Hash   *current_request  = 0;

static FILE* swill_temp_create(const char* tmpdir);
static FILE* swill_temp_use(void);
static void swill_temp_clear(FILE* ft);
static void swill_temp_delete(void);

/* -----------------------------------------------------------------------------
 * Utility functions for setting/getting headers and form vars
 * ----------------------------------------------------------------------------- */

static char *swill_getstr(const char* name)
{
   char* str = GetChar(current_request, name);
   return str;
}

char *swill_getrequest(void)
{
   return swill_getstr("request");
}

char *swill_getpeername(void)
{
   return swill_getstr("peername");
}

void swill_setheader(const char *header, const char *value) {
   Setattr(http_out_headers,header,value);
}

void swill_setresponse(const char *value) {
   if (http_response) Delete(http_response);
   http_response = NewString(value);
}

char *swill_getheader(const char *header) {
   Hash *headers;
   char temp[1024];
   char *c;
   strcpy(temp,header);
   c = temp;
   while (*c) {
      *c = tolower(*c);
      c++;
   }
   headers = Getattr(current_request,"headers");
   if (headers) {
      return GetChar(headers,temp);
   } else {
      return 0;
   }
}

char *swill_getvar(const char *name) {
   Hash *query = Getattr(current_request,"query");
   if (query) {
      return GetChar(query,name);
   }
   return 0;
}

int swill_getint(const char *name) {
   Hash *query = Getattr(current_request,"query");
   if (query) {
      return GetInt(query,name);
   }
   return 0;
}

double swill_getdouble(const char *name) {
   Hash *query = Getattr(current_request,"query");
   if (query) {
      return GetDouble(query,name);
   }
   return 0;
}

/* -----------------------------------------------------------------------------
 * swill_init()
 * ----------------------------------------------------------------------------- */

int
swill_init_ssl(int port, int ssl, const char* tmpdir) {

   assert(!SwillInit);

   swill_initialize_comm();

   if (!SwillFile) {
      SwillFile = swill_temp_create(tmpdir);
      assert(SwillFile);
   }

   SwillSocket = -1;
   SwillPort = 0;

#if defined(SWILL_SSL) && (SWILL_SSL > 0)
   SwillSSL = ssl;
   swill_ssl_init(SwillSSL);
#else
   SwillSSL = 0;
   if (ssl)
      swill_ssl_not_supported("swill_ssl_init");
#endif

#ifdef __USE_MPI
   /*MPI_Init(&argc, &argv); */
   /* we don't call MPI_Init(), we expect that the host code has done it for us.
    *  --TL 
    */
   MPI_Comm_size(MPI_COMM_WORLD,&_swill_mpi_numprocs);
   MPI_Comm_rank(MPI_COMM_WORLD,&_swill_mpi_rank);

#endif

   DohEncoding("url",swill_url_encoder);
   DohEncoding("pre",swill_pre_encoder);

#ifdef __USE_MPI
   if(_swill_mpi_rank == 0) {
#endif

      SwillSocket = swill_create_listening_socket(port);
      if (SwillSocket < 0) {
	 SwillSocket = -1;
	 SwillInit = SwillPort = 0;
	 goto init_ret;
      }
    
      /* Get port assigned to the socket */
      SwillPort = swill_get_assigned_port(SwillSocket);

#ifdef __USE_MPI
   } else {
      /* Need to place some initialization code here */
   }
#endif
   SwillTitle = NewString("SWILL");
   SwillDocroot = 0;
   SwillInit = 1;
   swill_security_init();

#if defined(SWILL_IGNORE_INFO) && (SWILL_IGNORE_INFO > 0)
#else
   swill_handle("info",SH(SwillListHandlers),0);
#endif
   
  init_ret:
#ifdef __USE_MPI
   MPI_Bcast(&SwillInit, 1,MPI_INT, 0, MPI_COMM_WORLD);
#endif
   return SwillPort;
}

/* -----------------------------------------------------------------------------
 * swill_shutdown()
 *
 * Close the server
 * ----------------------------------------------------------------------------- */

void 
swill_shutdown(void) {
   if (!SwillInit) return;

#if defined(SWILL_SSL) && (SWILL_SSL > 0)
   if (SwillSSL) {
      swill_ssl_term();
      SwillSSL = 0;
   }
#endif

   if (SwillSocket > 0)
      swill_close_socket(SwillSocket);

   fclose(SwillFile);
   SwillFile = 0;
   swill_temp_delete();

   Delete(SwillTitle);
   Delete(SwillDocroot);
   SwillSocket = 0;
   SwillTitle = 0;
   SwillDocroot = 0;
   SwillInit = 0;
   swill_handler_reset();
   swill_security_reset();

   swill_terminate_comm();
}

/* -----------------------------------------------------------------------------
 * swill_title()
 *
 * Set or return the server title.
 * ----------------------------------------------------------------------------- */

char *
swill_title(const char *title) {
   if (!SwillInit) return 0;
   if (title)
      SwillTitle = NewString(title);
   return Char(SwillTitle);
}

/* -----------------------------------------------------------------------------
 * swill_directory()
 *
 * Set the document root for serving arbitrary files.
 * ----------------------------------------------------------------------------- */

char *
swill_directory(const char *pathname) {
   if (!SwillInit) return 0;
   if (pathname) {
      if (SwillDocroot) Delete(SwillDocroot);
      if (strlen(pathname)) {
	 SwillDocroot = NewString(pathname);
      } else {
	 SwillDocroot = 0;
      }
   }
   return SwillDocroot ? Char(SwillDocroot) : 0;
}

/* -----------------------------------------------------------------------------
 * swill_timeout()
 *
 * Send the timeout value.
 * ----------------------------------------------------------------------------- */

void
swill_timeout(int timeout) {
   SwillTimeout =  timeout;
}

/* -----------------------------------------------------------------------------
 * check_filename()
 *
 * Checks a filename to see if it is legal or not.  Does not allow any
 * path component to start with a '.'
 * ----------------------------------------------------------------------------- */

static int 
check_filename(String *fn) {
   int ch;
   int state = 0;
   Seek(fn,0,SEEK_SET);
   while (1) {
      ch = Getc(fn);
      if (ch == EOF) return 1;
      if ((ch == '.') && (state)) return 0;
      if (ch == '.') state++;
      else state = 0;
   }
}

/* -----------------------------------------------------------------------------
 * swill_nbwrite()
 *
 * Non-blocking write to a socket
 * ----------------------------------------------------------------------------- */

static int
swill_nbwrite(int fd, char *buffer, int len) {
   int             nsent = 0;
   int             n;

   while (nsent < len) {
      if (! swill_sock_can_write(fd, SwillTimeout)) {
	 /* Timeout.  We're history. */
	 swill_logprintf("   Warning: write timeout!\n");
	 return nsent;
      }

      n = swill_sock_do_write(fd, buffer+nsent, len-nsent);
      if (n < 0)
	 return nsent;

      nsent += n;
   }
   return nsent;
}

static int
swill_nbcopydata(FILE *in, int fd) {
#define COPY_SIZE 16384

   char buffer[COPY_SIZE];
   int nread, nw;
   int total = 0;
   while (1) {
      nread = Read(in,buffer,COPY_SIZE);
      if (nread < 0) {
	 if (errno != EINTR) {
	    return total;
	 }
	 continue;
      }
      if (nread == 0) break;
      nw = swill_nbwrite(fd,buffer,nread);
      if (nw != nread) {
	 return total;
      }
      total += nread;
   }
   return total;
}

/* -----------------------------------------------------------------------------
 * swill_dump_page()
 *
 * Dumps the raw page to the socket.
 * ----------------------------------------------------------------------------- */

static int 
swill_dump_page(File *webpage, int fd) {
   String *tmp;
   String *key;
   int     nbytes;
   int     val;
  
   Seek(webpage, 0, SEEK_END);
   nbytes = Tell(webpage);
   Seek(webpage,0, SEEK_SET);

   val = swill_sock_set_nonblock(fd);
  
   tmp = NewStringf("HTTP/1.0 %s\n", http_response);
  
   if (swill_nbwrite(fd, Char(tmp), Len(tmp)) != Len(tmp)) {
      goto send_error;
   }
   key = Firstkey(http_out_headers);
   while (key) {
      Clear(tmp);
      Printf(tmp,"%s: %s\n", key, Getattr(http_out_headers,key));
      if (swill_nbwrite(fd, Char(tmp), Len(tmp)) != Len(tmp)) {
	 goto send_error;
      }
      key = Nextkey(http_out_headers);
   }
   Clear(tmp);
   if (nbytes) {
      Printf(tmp,"Content-Length: %d\n", nbytes);
   }
   Printf(tmp,"Server: SWILL/%d.%d\n", SWILL_MAJOR_VERSION, SWILL_MINOR_VERSION);
   Printf(tmp,"Connection: close\n");
   Printf(tmp,"\n");
   if (swill_nbwrite(fd, Char(tmp), Len(tmp)) != Len(tmp)) {
      goto send_error;
   }
  
   swill_nbcopydata(webpage,fd);

   swill_sock_restore_block(fd, val);

   if (tmp) Delete(tmp);
   return nbytes;
  send_error:
   if (tmp) Delete(tmp);
   swill_sock_restore_block(fd, val);
   return 0;
}

/* -----------------------------------------------------------------------------
 * swill_send_file()
 *
 * Send a file to the client.  Handle If-Modified-Since too.
 * ----------------------------------------------------------------------------- */

static void
swill_send_file(FILE *f, struct stat *info, FILE *out, int clientfd)
{
   char lastmod[256];
   String *ims;
   int ishead;

   SetInt(http_out_headers,"Content-Length",info->st_size);
   strftime(lastmod, sizeof lastmod,
	    "%a, %d %b %Y %H:%M:%S GMT", gmtime(&info->st_mtime));
   swill_setheader("Last-Modified", lastmod);
   ims = swill_getheader("if-modified-since");
   ishead = ims && strcmp(ims, lastmod) == 0;
   if (ishead) {
#if defined(GONZO_DEBUG) && (GONZO_DEBUG > 0)
      fprintf(stderr, "GONZO: file not modified, sending 304\n");
#endif
      swill_setresponse("304 Not Modified");
   }

   /* Dump web-page so far */
   swill_dump_page(out,clientfd);
   if (!ishead) {
      int val = swill_sock_set_nonblock(clientfd);
      swill_nbcopydata(f,clientfd);
      swill_sock_restore_block(clientfd, val);
   }
}

/* -----------------------------------------------------------------------------
 * swill_serve_file()
 *
 * Serves a local file.  Returns -1 if unsuccessful.
 * uri is the input URL, out is the output stream, and clientfd is the
 * integer fd of the socket.
 * ----------------------------------------------------------------------------- */

static int 
swill_serve_file(String *uri, File *out, int clientfd) {
   String *filename, *of;
   char *cfilename;
   FILE *f;
   int   fileok = 0;
   struct stat info;

   filename = NewString("");
   Printf(filename,"%s/%s",SwillDocroot,uri);

   if (SwillDocroot) {
      if (Strncmp(filename,SwillDocroot,Len(SwillDocroot)) == 0) {
	 String *tfilename = NewString(Char(filename)+Len(SwillDocroot));
	 fileok = check_filename(tfilename);
	 Delete(tfilename);
      }
   } else {
      fileok = check_filename(filename);
   }

   if (fileok) {
      /* Get some statistics about the file */
     filetry:
      cfilename = (char *) Data(filename);
      if (lstat(cfilename,&info) < 0) {
	 SwillFileNotFound(out,0);
	 Delete(filename);
	 return -1;
      }
      if (S_ISDIR(info.st_mode)) {
	 /* Hmmm. Appears to be a directory.  If the directory does not have a trailing "/"
	    We need to redirect the browser */
	 if (cfilename[strlen(cfilename)-1] != '/') {
	    swill_setresponse("301 Moved Permanently");
	    of = NewString("");
	    Printf(of,"http://%s/%s/", swill_getheader("host"), uri);
	    swill_setheader("location",(char *) of);
	    swill_setheader("Content-Type","text/html");
	    Printf(out,"<h1>Moved permanently</h1>\n");
	    Delete(filename);
	    return -1;
	 }
	 Printf(filename,"%s",SWILL_DEFAULT);
	 goto filetry;
      }
      f = fopen((char *)Data(filename),"r");
      if (!f) {
	 SwillFileNotFound(out,0); 
	 Delete(filename);
	 return -1;
      }

#if defined(GONZO_DEBUG) && (GONZO_DEBUG > 0)
      fprintf(stderr, "GONZO: sending local file [%s]\n",
	      cfilename);
#endif

      swill_setheader("Content-Type", swill_guess_mimetype(Char(filename)));
      swill_send_file(f, &info, out, clientfd);
      fclose(f);
      Delete(filename);
      return 0;
   } else {
      SwillFileNotFound(out,0);
      Delete(filename);
      return -1;
   }
}

/* -----------------------------------------------------------------------------
 * swill_serve_one()
 *
 * This function handles a raw http-request on a single processor. This is the
 * entry point to the server on a multiprocessor application.  Tasks performed
 * at this stage include:
 *
 *     -  Serving of simple files or directories
 *     -  User authentication
 *     -  Error messages for invalid web pages.
 *     -  Redirection.
 *
 * If the request was an error or applicable to a single processor, NULL is
 * returned. 
 *
 * Otherwise, an output object is returned and some global variables are set.
 * The caller can use this to figure out how to call the handling function.
 *
 * P.S. This function is a big mess...
 * ----------------------------------------------------------------------------- */

static FILE *
swill_serve_one(const char* clientaddr, int clientfd) 
{
   Hash         *handler;
   SwillHandler whandle;
   FILE        *out = 0;
   String      *excess;
   String      *requeststring;
   Hash        *request;
   String      *method;
   String      *peerip;


   /* Compute the peer IP address */
   peerip = NewString(clientaddr);

   /* Implement IP filtering here */
   if (!swill_check_ip(peerip)) {
      Delete(peerip);
      return 0;
   }

   swill_logprintf("%-15s ", peerip);

   /* Read the raw HTTP request */
   if (!swill_read_rawrequest(clientfd, &requeststring, &excess)) {
      /* Bad request. Too big, malformed, etc. */
      Delete(peerip);
      swill_logprintf("Bad request\n");
      return 0;
   }

   /* Try to parse into a request */
   request = swill_parse_request_headers(requeststring);
   if (!request) {
      Delete(peerip);
      Delete(excess);
      Delete(requeststring);
      swill_logprintf("Malformed request\n");
      return 0;
   }

   /* If we made it this far, the initial HTTP request looks valid */
   Delete(requeststring);

   method = Getattr(request,"method");

   /* If a logfile is available, print some information about the request */
   {
      time_t t;
      struct tm *tms;
      char ts[256];
      t = time(NULL);
      tms = localtime(&t);
      strftime(ts,64,"[%d %b %y %H:%M:%S]", tms);
      swill_logprintf("%s %s %s\n", ts, method, Getattr(request,"uri"));
   }

   Setattr(request,"peername", peerip);
   Delete(peerip);

   /* Handle query string data here */
   if (Strcmp(method,"POST") == 0) {
      int length;
      String *posts;
      Hash   *headers;
      requeststring = Getattr(request,"request");
      headers = Getattr(request,"headers");
      Seek(requeststring, 0, SEEK_END);
      Append(requeststring,excess);            /* Add excess data */
      length = GetInt(headers,"content-length");
      if (length > 0) {
	 posts = swill_read_post(clientfd,length,excess);
	 if (posts) {
	    if (Len(posts) > Len(excess)) {
	       Append(requeststring, Char(posts) + Len(excess));
	    }
	    Delete(posts);
	 } else {
	    Delete(excess);
	    Delete(request);
	    return 0;
	 }
      }
   }
   Delete(excess);

   if (!swill_parse_request_data(request)) {
      Delete(request);
      return 0;
   }

   /* Request has been parsed and all form variables are set */

   /* Set global variables */
   http_uri        = Getattr(request,"uri");
   current_request = request;

   /* Create output headers */

   http_out_headers = NewHash();
   /*  Setattr(http_out_headers,"Cache-Control","no-cache"); */
   Setattr(http_out_headers,"Expires","Sat, 1 Jan 2000 00:00:00 GMT");
   Setattr(http_out_headers,"Pragma","nocache");
   swill_setresponse("200 OK");

   /* Create an output object */
   out = swill_temp_use();

   /* Check for user authorization here */
   if (!swill_checkuser()) {
      SwillAuthenticate(out,0);
      Setattr(http_out_headers,"WWW-Authenticate","Basic");
      goto handled_request;
   }

   /* Check if method is valid */
   if (!(Strcmp(method,"GET") == 0) && !(Strcmp(method,"POST") == 0)) {
      SwillUnsupported(out,0);    
      goto handled_request;
   } 

   /* See if there is a handler function registered for this URI */
   handler = swill_handler_lookup(http_uri);
   if (handler) {
    
      /* A user handler was registered.  If it is the special "info" handler or a file, we just run it here.
	 Otherwise, we will return to the caller */
    
      /* Set default mime-type of return page */
    
      swill_setheader("Content-Type", GetChar(handler,"mimetype"));
      whandle = (SwillHandler) Data(Getattr(handler,"handler"));

      if (whandle) {

#if defined(SWILL_IGNORE_INFO) && (SWILL_IGNORE_INFO > 0)
#else
	 /* Only serve the handler if its the special info page */
	 if (Cmp(http_uri,"info") == 0) {
	    (*whandle)(out,Data(Getattr(handler,"clientdata")));
	    goto handled_request;
	 }
#endif

	 /* We actually got a valid request for something that we will 
	    return to the user.  In this case, we simply return the output object */

	 return out;
      } else {
	 /* No callback function.  A simple file */
	 FILE *f;
	 char *filename;
	 filename = Data(Getattr(handler,"filename"));
	 f = fopen(filename,"r");
	 if (!f) {
	    SwillFileNotFound(out,0); 
	    goto handled_request;
	 } else {
	    /* Find out the length */
	    struct stat info;
	    fstat(fileno(f),&info);
	    swill_send_file(f, &info, out, clientfd);
	    fclose(f);
	    out = 0;
	    goto handled_request;
	 }
      }
   }
  
   /* No handler registered.  Maybe we can pull something out of a directory of files */

   /* See if a document root has been set */
   if (!SwillDocroot) {
      SwillFileNotFound(out,0);
      goto handled_request;
   }
   if (swill_serve_file(http_uri,out,clientfd) >= 0) {
      out = 0;
   }

/* This code is called when the request has been handled by this function */

  handled_request:

   if (out) {
      /* Dump the web-page out.  We handled it on a single processor */
      fflush(out);
      swill_dump_page(out,clientfd);
      swill_temp_clear(out);
   }

   /* Cleanup */
   Delete(current_request);
   Delete(http_out_headers);
   return 0;
}

/* -----------------------------------------------------------------------------
 * swill_serve()
 * ----------------------------------------------------------------------------- */


#ifndef __USE_MPI
int
swill_serve(void) {
   char clientaddr[128];
   int clientfd;
   int oldstdout;

   FILE *out = 0;
   if (!SwillInit) {
      return 0;
   }
    
   /* Wait for a connection */
   /* This is where that DoS prevention code should go !! */
   clientfd = swill_accept_connection(SwillSocket, clientaddr);
   if (clientfd < 0) return 0;

   /* Go process request */
    
   out = swill_serve_one(clientaddr,clientfd);
   if (!out) {
      /* swill_serve_one() took care of everything.  Goodbye */
      swill_close_socket(clientfd);
      return 1;
   } else {
      SwillHandler  whandle;
      Hash         *handler;

      handler = swill_handler_lookup(http_uri);
      assert(handler);   /* we're hosed if this is broken */
    
      whandle = (SwillHandler) Data(Getattr(handler,"handler"));
      assert(whandle);

      /* Note : the stdout flag is set to capture stdout */
      if (Getattr(handler,"stdout")) {
	 /* This is a very sneaky horrible trick.  We swap in a new file descriptor for stdout. */
	 fflush(stdout);
	 oldstdout = dup(1);       /* Duplicate the file descriptor for stdout */
	 /* Now dup2 the output stream onto stdout */
	 dup2(fileno(out),1);
      }

      /* Call the handler */
      (*whandle)(out,Data(Getattr(handler,"clientdata")));

      if (Getattr(handler,"stdout")) {
	 /* Restore the old stdout file descriptor */
	 fflush(stdout);
	 dup2(oldstdout,1);
	 close(oldstdout);
      }
      fflush(out);
      /* Dump the web-page here */
      swill_dump_page(out,clientfd);
      swill_temp_clear(out);

      /* Delete the other fields */
      Delete(current_request);
      Delete(http_out_headers);
   }
   swill_close_socket(clientfd);
   return 1;
}

#elif defined __USE_MPI

/* MPI version */

int
swill_serve(void) {
   char clientaddr[128];
   int clientfd;
   int oldstdout;

   FILE *out = 0;

   String *request = 0;
   int request_len = 0;
   char *tmp_request = 0;

   if (!SwillInit) {
      return 0;
   }

   if ( _swill_mpi_rank == 0){
      /* Wait for a connection */
      /* This is where that DoS prevention code should go !! */
      clientfd = swill_accept_connection(SwillSocket, clientaddr);
      if (clientfd < 0){
	 request = 0;
	 goto bcast_serve;
      }
    
      out = swill_serve_one(clientaddr,clientfd);
      if (!out) {
	 swill_close_socket(clientfd);
	 request = 0;
	 goto bcast_serve;
      } else {
	 /* Need to regenerate a request to send to other nodes */
	 request = Getattr(current_request,"request");
	 request_len = Len(request);
	 tmp_request = Char(request);
      }
   } /* whether NULL or not, we have a request string. --TL */
  
  bcast_serve:
   MPI_Bcast(&request_len, 1, MPI_INT, 0, MPI_COMM_WORLD);
   if( request_len){
      if(_swill_mpi_rank){
	 tmp_request = (char *)malloc(sizeof(char) * request_len+1);
      }
    
      MPI_Bcast(tmp_request, request_len+1, MPI_CHAR, 0, MPI_COMM_WORLD);
    
      if(_swill_mpi_rank){
	 request = NewString(tmp_request);
      }
      free(tmp_request);
    
      /* now build up the information you need to execute this;
       * this obviates the need for setting the parameters accessible to node0, 
       * since it is easier for everyone to recompute them. --TL 
       */

      /* This function builds the needed data structures from
	 the received request string */
    
      if(_swill_mpi_rank){
	 current_request = swill_parse_request(request);
      }
      http_out_headers = NewHash();
      http_uri         = Getattr(current_request,"uri");
      /* We need to call the handler here */
      {
	 FILE *out;
	 String *tmp_merged_out;
	 SwillHandler  whandle;
	 Hash   *handler;
	 int    out_size = 0;
	 int    tmp_out_size = 0;
	 char   *tmp_out = 0;
	 String *tmp_out_string = 0;
	 int    i = 0;
	 MPI_Status status;
	 String *outs;

	 handler = swill_handler_lookup(http_uri);
	 assert(handler);   /* we're hosed if this is broken */
      
	 whandle = (SwillHandler) Data(Getattr(handler,"handler"));
	 assert(whandle);
      
	 /* Create an output object */
	 out = swill_temp_use();

	 swill_setheader("Content-Type", GetChar(handler,"mimetype"));
	 swill_setresponse("200 OK");

	 /* Note : the stdout flag is set to capture stdout */
	 if (Getattr(handler,"stdout")) {
	    /* This is a very sneaky horrible trick.  We swap in a new file descriptor for stdout. */
	    fflush(stdout);
	    oldstdout = dup(1);       /* Duplicate the file descriptor for stdout */
	    /* Now dup2 the output stream onto stdout */
	    dup2(fileno(out),1);
	 }

	 (*whandle)(out,Data(Getattr(handler,"clientdata")));

	 if (Getattr(handler,"stdout")) {
	    /* Restore the old stdout file descriptor */
	    fflush(stdout);
	    dup2(oldstdout,1);
	    close(oldstdout);
	 }
	 fflush(out);
	 out_size = Tell(out);
      	  
	 /* do fd initialization */
	 if( _swill_mpi_rank == 0){
	    tmp_out_string = NewString("");
	    /* first dump master */
	    Seek(out, 0, SEEK_SET);
	    Copyto(out, tmp_out_string);
	 }
      
	 for(i = 1; i < _swill_mpi_numprocs; i ++){
	
	    if( _swill_mpi_rank == i ){
	  
	       MPI_Send(&out_size, 1, MPI_INT, 0, i , MPI_COMM_WORLD);
	       outs = NewString("");
	       Seek(out, 0, SEEK_SET);
	       Copyto(out, outs);
	       MPI_Send(Char(outs), out_size, MPI_CHAR, 0, i + 1024, MPI_COMM_WORLD);
	       Delete(outs);
	  
	    } else if(_swill_mpi_rank == 0){
	  
	       MPI_Recv(&tmp_out_size, 1, MPI_INT, i, i, MPI_COMM_WORLD, &status);
	       tmp_out = (char*) malloc(sizeof(char)*tmp_out_size);
	       MPI_Recv(tmp_out, tmp_out_size, MPI_CHAR, i, i + 1024,
			MPI_COMM_WORLD, &status);
	       Write(tmp_out_string, tmp_out, tmp_out_size);
	    }
	 }
	 if( _swill_mpi_rank == 0){
	    swill_dump_page(tmp_out_string, clientfd);
	    Delete(tmp_out_string);
	    swill_close_socket(clientfd);
	 }
      }
      if(!_swill_mpi_rank == 0)
	 Delete(request);
    
      Delete(current_request);
      http_out_headers = 0;
      return 0;
   }
   else {
      /* probably just served a file
       * could also be one of a number of problems, 
       * what the heck! return 0
       */
      return 0;
   }
   /* everyone return 0? --TL */
   return 0;
}

#endif

/* -----------------------------------------------------------------------------
 * swill_poll()
 *
 * See if there are any pending connections and handle them if so. Otherwise
 * return.
 * ----------------------------------------------------------------------------- */
/* non MPI version */

#ifndef __USE_MPI

int swill_poll(void) {
   if (!SwillInit) return 0;

   if (! swill_sock_can_read(SwillSocket, 0))
      return 0;

#if 1
   return swill_serve();
#else
   if (FD_ISSET(SwillSocket,&rset)) {
      return swill_serve();
   } else {
      return 0;
   }
#endif
}

#endif

#ifdef __USE_MPI

/* MPI version of swill_poll() */

int swill_poll(void) {
   int serve_flag;
   int     ret;

   /* we use swill_poll() to reach some agreement as to whether we need to do 
    * something. swill_serve() will actually do the work. --TL 
    */
   if (!SwillInit) return 0;

   if(_swill_mpi_rank == 0 ){
      /* master */
      if (SwillSocket < 0) {
	 serve_flag = 0;
	 goto bcast_poll;
      }

      if (! swill_sock_can_read(SwillSocket, 0)) {
	 serve_flag = 0;
	 goto bcast_poll;
      }

#if 1
      serve_flag = 1;
#else
      if (FD_ISSET(SwillSocket,&rset)) {
	 serve_flag = 1;
      } else {
	 serve_flag = 0;
      }
#endif
   }
  bcast_poll:
   /* rank independent: broadcast decision and act on it. --TL */
   MPI_Bcast(&serve_flag, 1, MPI_INT, 0, MPI_COMM_WORLD);
   if( serve_flag ){
      return swill_serve();
   }
   return 0;
}
#endif

void swill_netscape(const char *url) {
   char buffer[2048];
   sprintf(buffer,"netscape -remote 'openURL(http://localhost:%d/%s)'", SwillPort, url);
   system(buffer);
}

static FILE* swill_temp_create(const char* tmpdir)
{
   SwillFName[0] = '\0';

   if (tmpdir == 0 || tmpdir[0] == '\0')
      return tmpfile();
   else
   {
      FILE* ft = 0;

#if defined(WIN32)
      int r;
      char prefix[4];

      srand((unsigned )time(NULL));
      r = rand() % 1000;
      sprintf(prefix, "%03d", r);
      if (GetTempFileName(tmpdir,
			  prefix,
			  0, // create unique name
			  SwillFName)) // buffer for name
	 ft = fopen(SwillFName, "w+b");
#else
      int fd;

      sprintf(SwillFName, "%s/XXXXXX", tmpdir);
      fd = mkstemp(SwillFName);
      if (fd != 0)
	 ft = fdopen(fd, "w+b");
#endif

      return ft;
   }  
}

static FILE* swill_temp_use(void)
{
   FILE* ft = SwillFile;
   swill_temp_clear(ft);
   return ft;
}

static void swill_temp_clear(FILE* ft)
{
   ftruncate(fileno(ft),0);
   fseek(ft,0, SEEK_SET);
}

static void swill_temp_delete(void)
{
   if (SwillFName[0] != '\0')
   {
      remove(SwillFName);
      SwillFName[0] = '\0';
   }
}
