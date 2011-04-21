/* Cmake rox, nothing less! Now SniffJoke will see the light at the end of the tunnel, I hope */

#ifndef CONFIG_H
#define CONFIG_H
       
/* Define to 1 if you have the `clock_gettime' function. */
/* #undef HAVE_CLOCK_GETTIME */
/* "use syscall interface for clock_gettime" */
/* #undef HAVE_CLOCK_SYSCALL */
/* Define to 1 if you have the `epoll_ctl' function. */
/* #undef HAVE_EPOLL_CTL */
/* Define to 1 if you have the `eventfd' function. */
/* #undef HAVE_EVENTFD */
/* Define to 1 if you have the `inotify_init' function. */
/* #undef HAVE_INOTIFY_INIT */
/* Define to 1 if you have the `kqueue' function. */
/* #undef HAVE_KQUEUE */
/* Define to 1 if you have the `nanosleep' function. */
/* #undef HAVE_NANOSLEEP */
/* Define to 1 if you have the `poll' function. */
/* #undef HAVE_ERRNO_H */
/* #undef HAVE_ERRNO */

/* ***
 * yes yes yes: before the 1.0 release, SniffJoke will use libevent 
 \****          ^^^^^^ ^^^ ^^^ ^^^^^^^  ^^^^^^^^^ ^^^^ ^^^ ^^^^^^^^  */

/* #undef HAVE_POLL */
/* Define to 1 if you have the <poll.h> header file. */
/* #undef HAVE_POLL_H */
/* Define to 1 if you have the `select' function. */
/* #undef HAVE_SELECT */
/* Define to 1 if you have the <sys/epoll.h> header file. */
/* #undef HAVE_SYS_EPOLL_H */
/* Define to 1 if you have the <sys/eventfd.h> header file. */
/* #undef HAVE_SYS_EVENTFD_H */
/* Define to 1 if you have the <sys/event.h> header file. */
/* #undef HAVE_SYS_EVENT_H */

/* end of the libevent wishlist: hey! if you know libevent and feel
 * yourself strangely attracted from sniffjoke, help us! */

/* Define to 1 if you have the <sys/inotify.h> header file. */
/* #undef HAVE_SYS_INOTIFY_H */
/* Define to 1 if you have the <sys/queue.h> header file. */
/* #undef HAVE_SYS_QUEUE_H */
/* Define to 1 if you have the <sys/select.h> header file. */
/* #undef HAVE_SYS_SELECT_H */

/* where can I find the sniffjoke executable ? */
#define PREFIX "/usr/local"

#define INSTALL_BINDIR PREFIX"/bin"

/* the prefix and the exec_prefix passed by configure - compatibility */
#define INSTALL_EXECPREFIX PREFIX
#define INSTALL_PREFIX PREFIX

/* where can I find my plugins ? */
#define INSTALL_LIBDIR PREFIX"/lib/sniffjoke/"

/* where can I find my running track ? */
#define INSTALL_STATEDIR PREFIX"/var/sniffjoke/"

/* #undef SNIffJOKE_VERSION_MAJOR */
/* #undef SNIffJOKE_VERSION_MINOR */
/* #undef SNIffJOKE_VERSION_SUffIX */

/* Version number of package */
#ifdef SNIffJOKE_VERSION_SUffIX
#define VERSION SNIffJOKE_VERSION_MAJOR"."SNIffJOKE_VERSION_MINOR"-"SNIffJOKE_VERSION_SUffIX
#else
#define VERSION SNIffJOKE_VERSION_MAJOR"."SNIffJOKE_VERSION_MINOR
#endif

/* Name of package */
#define PACKAGE PROJECT
#define PACKAGENAME PACKAGE"-"VERSION

#endif // CONFIG_H
