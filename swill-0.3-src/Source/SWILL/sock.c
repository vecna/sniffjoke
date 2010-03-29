/* ----------------------------------------------------------------------------- 
 * sock.c
 *
 *     This file contains code to work with sockets for I/O.
 * 
 * Author(s) : Gonzalo Diethelm (gonzo@diethelm.org)
 *
 * See the file LICENSE for information on usage and redistribution.	
 * ----------------------------------------------------------------------------- */

static char cvsroot[] = "$Header: /cvsroot/swill/SWILL/Source/SWILL/sock.c,v 1.8 2008/04/10 03:55:01 gonzalodiethelm Exp $";

#if defined(WIN32)

#include <winsock.h>

#define EWOULDBLOCK WSAEWOULDBLOCK
#define comm_errno WSAGetLastError()

#else

#include <unistd.h>
#include <fcntl.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <signal.h>

#define comm_errno errno
#define closesocket(s) close(s)

static sig_t old_pipe;

#endif

#include "swillint.h"
#include "ssl.h"
#include "sock.h"

#if ! defined(GONZO_DEBUG)
#define GONZO_DEBUG 0
#endif

static int set_nonblock(int socket);
static int restore_block(int socket, int mode);

#if defined(WIN32)
static int inet_aton(const char* addr,
		     struct in_addr* ia);
#endif

void 
swill_initialize_comm(void)
{
#if defined(WIN32)
   /* Initialize Winsock. */
   WSADATA wsaData;
   WSAStartup(MAKEWORD(2,2), &wsaData);
#else
   /* Ignore broken pipe signal. */
   old_pipe = signal(SIGPIPE, SIG_IGN);
#endif

#if defined(GONZO_DEBUG) && (GONZO_DEBUG > 0)
   fprintf(stderr, "GONZO: Initialized communications\n");
#endif
}

void 
swill_terminate_comm(void)
{
#if defined(WIN32)
   /* Terminate Winsock. */
   WSACleanup();
#else
   signal(SIGPIPE, old_pipe);
#endif

#if defined(GONZO_DEBUG) && (GONZO_DEBUG > 0)
   fprintf(stderr, "GONZO: Terminated communications\n");
#endif
}

static char swill_if[32];

int 
swill_set_interface(const char* address)
{
   if (address == 0 || address[0] == '\0')
      swill_if[0] = '\0';
   else
      strcpy(swill_if, address);
   return 1;
}

int 
swill_create_listening_socket(int port)
{
   int sock = -1;
   int flag = 1;
   struct in_addr ia;
   struct sockaddr_in addr;

   /* Open up the server socket */
   sock = socket(AF_INET, SOCK_STREAM, 0);
   if (sock < 0) {
#if defined(GONZO_DEBUG) && (GONZO_DEBUG > 0)
      fprintf(stderr, "GONZO: Can't create socket!\n");
#endif
      return -1;
   }
  
   /* Re-use the address if possible */
   if (setsockopt(sock, SOL_SOCKET, SO_REUSEADDR,
		  (char *) &flag, sizeof(int)) < 0) {
      perror("setsockopt");
   }
  
   /* Set the server address */
   memset(&addr, 0, sizeof(addr));
   addr.sin_family = AF_INET;
   addr.sin_port = htons((unsigned short) port);

   if (swill_if[0] != '\0' &&
       inet_aton(swill_if, &ia))
   {
      /* If passed a valid interface, bind only there */
      addr.sin_addr = ia;
   }
   else
   {
      /* Bind to all interfaces */
      addr.sin_addr.s_addr = htonl(INADDR_ANY);
   }

   /* Bind the socket to the port */
   if (bind(sock,
	    (struct sockaddr *) &addr,
	    sizeof(addr)) < 0) {
      perror("bind");
#if defined(GONZO_DEBUG) && (GONZO_DEBUG > 0)
      fprintf(stderr, "GONZO: Can't bind to port %d!\n", port);
#endif
      closesocket(sock);
      return -1;
   }
    
   /* Allow, at most, 5 outstanding network connections */ 
   if (listen(sock, 5) < 0) {
      perror("listen");
   }

#if defined(GONZO_DEBUG) && (GONZO_DEBUG > 0)
   fprintf(stderr, "GONZO: Created listening socket %d on port %d\n",
	   sock, port);
#endif

   return sock;
}

int 
swill_get_assigned_port(int sock)
{
   struct sockaddr_in socketname;
   unsigned int inlen = sizeof(socketname);
   int port = -1;

   if (sock >= 0 &&
       getsockname(sock, (struct sockaddr *) &socketname,  &inlen) >= 0)
      port = ntohs(socketname.sin_port);

#if defined(GONZO_DEBUG) && (GONZO_DEBUG > 0)
   fprintf(stderr, "GONZO: Got assigned port for socket %d: %d\n",
	   sock, port);
#endif

   return port;
}

int 
swill_accept_connection(int sock, char* address)
{
   struct sockaddr_in addr;
   unsigned int len = sizeof(addr);
   int accepted = -1;

   address[0] = '\0';
   accepted = accept(sock, (struct sockaddr *) &addr, &len);
   if (accepted >= 0)
      strcpy(address, inet_ntoa(addr.sin_addr));

#if defined(GONZO_DEBUG) && (GONZO_DEBUG > 0)
   fprintf(stderr, "GONZO: Accepted connection on socket %d from [%s]\n",
	   accepted, address);
#endif

   if (SwillSSL && accepted >= 0) {
      swill_ssl_accept(accepted);
   }

   return accepted;
}

void 
swill_close_socket(int sock)
{
   if (SwillSSL) {
      swill_ssl_close(sock);
   }

   closesocket(sock);

#if defined(GONZO_DEBUG) && (GONZO_DEBUG > 0) 
   fprintf(stderr, "GONZO: Closed socket %d\n",
	   sock);
#endif
}

int 
swill_sock_set_nonblock(int sock)
{
   int old = -1;

   old = set_nonblock(sock);
#if defined(GONZO_DEBUG) && (GONZO_DEBUG > 0)
   fprintf(stderr, "GONZO: Set nonblock on socket %d, old value was %d\n",
	   sock, old);
#endif

   return old;
}  

void
swill_sock_restore_block(int sock, int value)
{
   restore_block(sock, value);

#if defined(GONZO_DEBUG) && (GONZO_DEBUG > 0)
   fprintf(stderr, "GONZO: Restored block on socket %d to value %d\n",
	   sock, value);
#endif
}  

int 
swill_sock_can_read(int sock, int timeout)
{
   fd_set reading;
   struct timeval tv;
   int retval;

   FD_ZERO(&reading);
   FD_SET(sock, &reading);
   tv.tv_sec = timeout;
   tv.tv_usec = 0;
   retval = select(sock + 1, &reading, NULL, NULL, &tv);

#if defined(GONZO_DEBUG) && (GONZO_DEBUG > 0)
   fprintf(stderr, "GONZO: Can read is %d\n",
	   retval);
#endif

   return (retval > 0);
}

int
swill_sock_do_read(int sock, char* buffer, unsigned int length)
{
   int nread;

   if (SwillSSL) {
      nread = swill_ssl_read(sock, buffer, length);
   } else {
      nread = recv(sock, buffer, length, 0);
   }

#if defined(GONZO_DEBUG) && (GONZO_DEBUG > 0)
   fprintf(stderr, "GONZO: Read %d out of %d bytes\n",
	   nread, length);
#endif

   if (nread > 0)
      return nread;

   if (comm_errno == EINTR)
      return 0;   /* Read interrupted, can try again. */

   return -1;    /* Read error. */
}


int 
swill_sock_can_write(int sock, int timeout)
{
   fd_set writing;
   struct timeval tv;
   int retval;

   FD_ZERO(&writing);
   FD_SET(sock, &writing);    
   tv.tv_sec = timeout;
   tv.tv_usec = 0;
   retval = select(sock + 1, NULL, &writing, NULL, &tv);

#if defined(GONZO_DEBUG) && (GONZO_DEBUG > 0)
   fprintf(stderr, "GONZO: Can write is %d\n",
	   retval);
#endif

   return (retval > 0);
}

int
swill_sock_do_write(int sock, char* buffer, unsigned int length)
{
   int nwritten;

   if (SwillSSL) {
      nwritten = swill_ssl_write(sock, buffer, length);
   } else {
      nwritten = send(sock, buffer, length, 0);
   }

#if defined(GONZO_DEBUG) && (GONZO_DEBUG > 0)
   fprintf(stderr, "GONZO: Wrote %d out of %d bytes\n",
	   nwritten, length);
#endif

   if (nwritten > 0)
      return nwritten;

   if (nwritten == 0 ||
       comm_errno == EWOULDBLOCK)
      return 0;   /* Write blocked, can try again. */

   return -1;    /* Write error. */
}


#if defined(WIN32)

static int set_nonblock(int socket)
{
   restore_block(socket, 1);
   return 0;
}

static int restore_block(int socket, int mode)
{
   ioctlsocket(socket, FIONBIO, &mode);
   return 0;
}

static int inet_aton(const char* addr,
		     struct in_addr* ia)
{
   DWORD ip = inet_addr(addr);
   memset(ia, 0, sizeof(struct in_addr));
   if (ip == INADDR_NONE)
      return 0;

   ia->S_un.S_addr = ip;
   return 1;
}

#else

static int set_nonblock(int socket)
{
   int mode = fcntl(socket, F_GETFL, 0);
   fcntl(socket, F_SETFL, mode | O_NONBLOCK);
   return mode;
}

static int restore_block(int socket, int mode)
{
   fcntl(socket, F_SETFL, mode);
   return 0;
}

#endif
