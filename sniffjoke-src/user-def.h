/*
 * this is the define value used in sniffjoke. if you are making porting of sniffjoke
 * for a distribution, this is your file
 */

#ifndef USERDEF_H
#define USERDEF_H

/* Sniffjoke defaults config values */
#define CONF_FILE 			"/root/.sniffjoke.binconf"
#define DROP_USER 			"nobody"
#define DROP_GROUP			"users"
#define CHROOT_DIR			"/tmp/sniffjoke"
#define LOGFILE				"sniffjoke.log" // it is used INSIDE chroot if not otherwise specified 
#define DEFAULT_DEBUG_LEVEL		0
#define SW_NAME				"SniffJoke"
#define SW_VERSION			"0.4 alpha 3"

#define SJ_SERVICE_LOCK			"/tmp/.sniffjoke_service.lock"
#define SJ_CLIENT_LOCK               	"/tmp/.sniffjoke_client.lock"
#define SJ_SERVICE_FATHER_PID_FILE	"/tmp/sniffjoke_father.pid"
#define SJ_SERVICE_CHILD_PID_FILE	"/tmp/sniffjoke_child.pid"
/* those are used under chroot */
#define SJ_SERVICE_UNIXSOCK		"sniffjoke_service" 
#define SJ_CLIENT_UNIXSOCK		"sniffjoke_client" 

#endif /* USERDEF_H */
