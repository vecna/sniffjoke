/*
 *   SniffJoke is a software able to confuse the Internet traffic analysis,
 *   developed with the aim to improve digital privacy in communications and
 *   to show and test some securiy weakness in traffic analysis software.
 *   
 *   Copyright (C) 2010 vecna <vecna@delirandom.net>
 *                      evilaliv3 <giovanni.pellerano@evilaliv3.org>
 *
 *   This program is free software: you can redistribute it and/or modify
 *   it under the terms of the GNU General Public License as published by
 *   the Free Software Foundation, either version 3 of the License, or
 *   (at your option) any later version.
 *
 *   This program is distributed in the hope that it will be useful,
 *   but WITHOUT ANY WARRANTY; without even the implied warranty of
 *   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *   GNU General Public License for more details.
 *
 *   You should have received a copy of the GNU General Public License
 *   along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */

#include <config.h>

/*
 * this is the define value used in sniffjoke. if you are making porting of sniffjoke
 * for a distribution, this is your file
 */

#ifndef SJ_DEFINES_H
#define SJ_DEFINES_H

#define SW_NAME                 "SniffJoke"
#define SW_VERSION              "0.4-beta4"

/* Sniffjoke defaults config values */

/* process information */
#define DROP_USER               "nobody"
#define DROP_GROUP              "nogroup"
#define WORK_DIR                INSTALL_STATEDIR
#define DEFAULT_LOCATION        "generic"

/* configuration file */
#define FILE_CONF               "sniffjoke-service.conf"
#define FILE_PLUGINSENABLER     "plugins-enabled.conf"
#define FILE_TTLFOCUSMAP        "ttlfocusmap.bin"
#define FILE_IPWHITELIST        "ipwhitelist.conf"
#define FILE_IPBLACKLIST        "ipblacklist.conf"
#define FILE_AGGRESSIVITY       "port-aggressivity.conf"
#define FILE_LOG                "sniffjoke.log"
#define FILE_LOG_SESSION       "sniffjoke.log.sessions"
#define FILE_LOG_PACKET        "sniffjoke.log.packets"

/* fixed value */
#define DEFAULT_DEBUG_LEVEL     2
#define DEFAULT_ADMIN_ADDRESS   "127.0.0.1"
#define DEFAULT_ADMIN_PORT      8844
#define SJ_PIDFILE              "/var/run/sniffjoke.pid"

// sorry, for double negation:
#define DEFAULT_START_STOPPED   false
// sniffjoke start stopped
// and is false to be true
// ( http://freeworld.thc.org/root/phun/unmaintain.html )

/* the maximum value of bruteforced TTL */
#define MAX_TTLPROBE                35
#define STARTING_ARB_TTL            46
#define TTLPROBE_RETRY_ON_UNKNOWN   600    /* seconds (10 MINUTES) */

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
#define MTU                     1500
#define MTU_FAKE                1420
/* this is not configurabile anyway in some (wrong) local network the
 * class 1.0.0.0/8 is used and should be require change this puppet-IP */
#define DEFAULT_FAKE_IPADDR     "1.198.10.5"

#define MSGBUF                  512

#define TCPTRACK_QUEUE_MAX_LEN                  1024
#define SESSIONTRACKMAP_MANAGE_ROUTINE_TIMER    300     /* (5 MINUTES */
#define TTLFOCUSMAP_MANAGE_ROUTINE_TIMER        3600    /* (1 HOUR) */
#define SESSIONTRACK_EXPIRYTIME                 200     /* access expire time in seconds (5 MINUTES) */
#define TTLFOCUS_EXPIRYTIME                     604800  /* access expire time in seconds (1 WEEK) */
#define HACKHASH_EXPIRYTIME                     10       /* hash expire time in seconds since creation (10 SECONDS)*/
#define HACKCACHE_EXPIRYTIME                    200     /* access expire time in seconds (5 MINUTES) */
#define TTLFOCUSMAP_MEMORY_THRESHOLD            1024    /* 1024 DESTINATIONS */
#define SESSIONTRACKMAP_MEMORY_THRESHOLD        1024    /* 1024 TCP SESSIONS */

#endif /* SJ_DEFINES_H */