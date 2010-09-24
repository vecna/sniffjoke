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
#define CONFIGURABLE_HACKS_N            12
#define ASSURED_HACKS                   "YYYYNNYYYYY"

#define SJ_SERVICE_LOCK			"/tmp/.sniffjoke_service.lock"
#define SJ_CLIENT_LOCK               	"/tmp/.sniffjoke_client.lock"
#define SJ_SERVICE_FATHER_PID_FILE	"/tmp/sniffjoke_father.pid"
#define SJ_SERVICE_CHILD_PID_FILE	"/tmp/sniffjoke_child.pid"
/* those are used under chroot */
#define SJ_SERVICE_UNIXSOCK		"sniffjoke_service" 
#define SJ_CLIENT_UNIXSOCK		"sniffjoke_client"

#define MTU				1500
#define MTU_FAKE			1440
#define MSGBUF				512

#endif /* SJ_DEFINES_H */
