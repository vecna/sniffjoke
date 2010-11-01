/*
 * this is the define value used in sniffjoke. if you are making porting of sniffjoke
 * for a distribution, this is your file
 */

#ifndef SJ_DEFINES_H
#define SJ_DEFINES_H

#define SW_NAME                         "SniffJoke"
#define SW_VERSION                      "0.4 alpha 3"

/* Sniffjoke defaults config values */
#define DROP_USER                       "sniffjoke"
#define DROP_GROUP                      "sniffjoke"
#define MAGICVAL			0xADECADDE
#define CHROOT_DIR			"/var/sniffjoke/"
// FIXME con -DPATH_LIB=\"$(libdir)/@PACKAGE@/\"
// #define PLUGINSSUBDIR			"/usr/local/lib/sniffjoke/"	// used INSIDE chroot
#define PLUGINSENABLER			"plugins_enabled.txt" // used INSIDE chroot
#define MAXPLUGINS			32
#define CONF_FILE 			"sjconf.bin"     //used INSIDE chroot
#define LOGFILE                         "sniffjoke.log"  //used INSIDE chroot
#define DEFAULT_DEBUG_LEVEL             2

#define SJ_PIDFILE			"/var/run/sniffjoke.pid"

/* those are used under chroot */
#define SJ_SERVICE_UNIXSOCK		"sniffjoke_service" 
#define SJ_CLIENT_UNIXSOCK		"sniffjoke_client"

/* TTL related define */
#define TTLFOCUSMAP_FILE		"ttlfocus.bin"   //used INSIDE chroot

/* the maximum value of bruteforced TTL */
#define STARTING_ARB_TTL		46



/*
  sniffoke make use of two MTU values, one real an one fake
  the real one is used on netfd(network real interface),
  the fake one instead is used on tunfd(the tun interface)
  the difference in values of 80 bytes is keept due to
  space requirements for tcp+ip options injection (40bytes + 40bytes).
  In fact ip header len has a minimum value of 5(20bytes)
  and a max value of 15(60bytes)  and so tcp data offset.
  So the difference between   min and max is 8(40bytes).
 */
#define MTU				1500
#define MTU_FAKE			1420


#define MSGBUF				512

#endif /* SJ_DEFINES_H */
