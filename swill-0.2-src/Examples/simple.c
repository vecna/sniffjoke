#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "swill/swill.h"

/* Define this to the port where you want to listen: */
#define SIMPLE_PORT 8080

/* Define this to the number of iterations you want the server to run: */
#define SIMPLE_TOP 0

/* Define this to 1 if you wish to dump the raw request to stderr: */
#define SIMPLE_DUMP 0

/* Users can use the command line to define this to 1 to use SSL (https): */
static int use_ssl = 0;

#if defined(WIN32)
#define SIMPLE_BASE "../../../"
#else
#include <unistd.h>
#define SIMPLE_BASE "./"
#endif

#define SIMPLE_SOURCE SIMPLE_BASE "../"

static void dump_request(FILE* out)
{
#if defined(SIMPLE_DUMP) && (SIMPLE_DUMP > 0)
   fprintf(out,
	   "Raw request:\n---------\n%s\n---------\n",
	   swill_getrequest());
#endif
}

void foo()
{
   int i;

   dump_request(stderr);

   printf("Hi, I'm foo.\n");
   for (i = 0; i < 10; i++) {
      printf("%d\n",i);
   }
}

/* A function that prints some HTML. Ok, this sucks in C */
void print_form(FILE *f)
{
   dump_request(stderr);

   fprintf(f,
	   "<HTML>\n"
	   " <form action=\"%s://localhost:%d/blah.html\"\n"
	   "  method=POST>\n",
	   use_ssl ? "https" : "http", SIMPLE_PORT);
   fprintf(f,
	   "Your name:\n"
	   "<input type=text name=name width=30></input><br>\n");
   fprintf(f,
	   "Submit:\n"
	   "<input type=submit></input>\n");
   fprintf(f,
	   " </form>\n"
	   "</html>\n");
}

/* A function that gets a form variable */
void print_name(FILE *f)
{
   char *name;

   dump_request(stderr);

   if (!swill_getargs("s(name)",&name)) {
      fprintf(f,"Hey, go enter your name.\n");
      return;
   }
   fprintf(f,"Your name is %s\n", name);
}

/* A function to return a password for the SSL certificate file */
int pwd_getter(char* buf, int maxlen)
{
   strcpy(buf, "password");
   return strlen(buf);
}

int main(int argc, char* argv[])
{
   int cnt = 0;

   use_ssl = (argc > 1 && strcmp(argv[1], "1") == 0);

   printf("Hello World!\n");
   if (swill_init_ssl(SIMPLE_PORT, use_ssl, 0)) {
      printf("SWILL listening on port %d, %susing SSL\n",
	     SIMPLE_PORT, use_ssl ? "" : "not ");

      /* If using SSL, we inform about our server certificate files. */
      if (use_ssl)
	 swill_ssl_set_certfile(SIMPLE_BASE "server.crt",
				SIMPLE_BASE "server.key",
				&pwd_getter);
   } else {
      printf("Couldn't initialize the server.\n");
      exit(1);
   }

   /* Set a default title for the pages. */
   swill_title("SWILL Example");

   /* Set a bunch of handlers. */
   swill_handle("stdout:foo.txt", foo, 0);
   swill_handle("form.html", print_form,0);
   swill_handle("blah.html", print_name,0);
   swill_file("README.txt", SIMPLE_SOURCE "README");
   swill_log(stdout);

   /* Serve files out of a directory */
   swill_directory(SIMPLE_SOURCE "Doc");

   /* Serve at most SIMPLE_TOP files. */
   /* If SIMPLE_TOP is zero make this loop infinite. */
   while (1) {
      ++cnt;
      swill_serve();
      if (SIMPLE_TOP > 0 && cnt >= SIMPLE_TOP)
	 break;
   }

   swill_shutdown();
}
