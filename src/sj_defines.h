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
#define CHROOT_DIR			"/tmp/sniffjoke"
#define CONF_FILE 			"sjconf.bin"     //used INSIDE chroot
#define TTLFOCUSMAP_FILE		"ttlfocus.bin"   //used INSIDE chroot
#define LOGFILE                         "sniffjoke.log"  //used INSIDE chroot
#define DEFAULT_DEBUG_LEVEL             2
#define CONFIGURABLE_HACKS_N            13
#define ASSURED_HACKS                   "NYNYYYNNYNNYY"

#define SJ_SERVICE_LOCK			"/tmp/.sniffjoke_service.lock"
#define SJ_CLIENT_LOCK               	"/tmp/.sniffjoke_client.lock"
#define SJ_SERVICE_FATHER_PID_FILE	"/tmp/sniffjoke_father.pid"
#define SJ_SERVICE_CHILD_PID_FILE	"/tmp/sniffjoke_child.pid"
/* those are used under chroot */
#define SJ_SERVICE_UNIXSOCK		"sniffjoke_service" 
#define SJ_CLIENT_UNIXSOCK		"sniffjoke_client"


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
