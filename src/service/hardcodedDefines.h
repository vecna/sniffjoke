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
#define DEFAULT_DIR             INSTALL_STATEDIR
#define DEFAULT_LOCATION        "generic"
#define DEFAULT_USER            "nobody"
#define DEFAULT_GROUP           "nogroup"
#define DEFAULT_ADMIN_ADDRESS   "127.0.0.1"
#define DEFAULT_ADMIN_PORT      8844
#define DEFAULT_CHAINING        false
#define DEFAULT_NO_TCP          false
#define DEFAULT_NO_UDP          false
#define DEFAULT_USE_WHITELIST   false
#define DEFAULT_USE_BLACKLIST   false
#define DEFAULT_DEBUG_LEVEL     2
#define DEFAULT_START_STOPPED   false /* sniffjoke start stopped and is false to be true
                                         (http://freeworld.thc.org/root/phun/unmaintain.html)*/
#define DEFAULT_GO_FOREGROUND   false
#define DEFAULT_MAX_TTLPROBE    35

/* this is not configurabile anyway in some (wrong) local network the
 * class 1.0.0.0/8 is used and should be require change this puppet-IP */
#define DEFAULT_FAKE_IPADDR     "1.198.10.5"

/* configuration dirs/files */
#define WORK_DIR                INSTALL_STATEDIR
#define SJ_PIDFILE              "/var/run/sniffjoke.pid"
#define FILE_CONF               "sniffjoke-service.conf"
#define FILE_PLUGINSENABLER     "plugins-enabled.conf"
#define FILE_TTLFOCUSMAP        "ttlfocusmap.bin"
#define FILE_IPWHITELIST        "ipwhitelist.conf"
#define FILE_IPBLACKLIST        "ipblacklist.conf"
#define FILE_AGGRESSIVITY       "port-aggressivity.conf"
#define FILE_LOG                "sniffjoke.log"
#define FILE_LOG_SESSION        "sniffjoke.log.sessions"
#define FILE_LOG_PACKET         "sniffjoke.log.packets"

#define SMALLBUF                64
#define MEDIUMBUF               256
#define LARGEBUF                1024
#define HUGEBUF                 4096
#define GARGANTUABUF            16384

#define SUPPRESS_LEVEL          0
#define ALL_LEVEL               1
#define ALL_LEVEL_NAME          "default"
#define VERBOSE_LEVEL           2
#define VERBOSE_LEVEL_NAME      "verbose"
#define DEBUG_LEVEL             3
#define DEBUG_LEVEL_NAME        "debug"
#define SESSION_LEVEL           4
#define SESSION_LEVEL_NAME      "sessions"
#define PACKET_LEVEL            5
#define PACKET_LEVEL_NAME       "packets"
#define TESTING_LEVEL           6
#define TESTING_LEVEL_NAME      "testing"

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
#define MTU_FAKE                11420

#define PORTSNUMBER             65536

#define SCRAMBLE_TTL            1
#define SCRAMBLE_TTL_STR        "PRESCRIPTION"
#define SCRAMBLE_CHECKSUM       2
#define SCRAMBLE_CHECKSUM_STR   "GUILTY"
#define SCRAMBLE_MALFORMED      4
#define SCRAMBLE_MALFORMED_STR  "MALFORMED"
#define SCRAMBLE_INNOCENT       8
#define SCRAMBLE_INNOCENT_STR   "INNOCENT"

#define AGG_NONE                1
#define AGG_N_NONE              "NONE"
#define AGG_VERYRARE            2
#define AGG_N_VERYRARE          "VERYRARE"
#define AGG_RARE                4
#define AGG_N_RARE              "RARE"
#define AGG_COMMON              8
#define AGG_N_COMMON            "COMMON"
#define AGG_HEAVY               16
#define AGG_N_HEAVY             "HEAVY"
#define AGG_ALWAYS              32
#define AGG_N_ALWAYS            "ALWAYS"
#define AGG_PACKETS10PEEK       64
#define AGG_N_PACKETS10PEEK     "PEEK10PKT"
#define AGG_PACKETS30PEEK       128
#define AGG_N_PACKETS30PEEK     "PEEK30PKT"
#define AGG_TIMEBASED5S         256
#define AGG_N_TIMEBASED5S       "EVERY5SECONDS"
#define AGG_TIMEBASED20S        512
#define AGG_N_TIMEBASED20S      "EVERY20SECONDS"
#define AGG_STARTPEEK           1024
#define AGG_N_STARTPEEK         "PEEKATSTART"
#define AGG_LONGPEEK            2048
#define AGG_N_LONGPEEK          "LONGPEEK"

#define TCPTRACK_QUEUE_MAX_LEN                  1024
#define SESSIONTRACKMAP_MANAGE_ROUTINE_TIMER    300     /* (5 MINUTES */
#define TTLFOCUSMAP_MANAGE_ROUTINE_TIMER        3600    /* (1 HOUR) */
#define SESSIONTRACK_EXPIRYTIME                 200     /* access expire time in seconds (5 MINUTES) */
#define TTLFOCUS_EXPIRYTIME                     604800  /* access expire time in seconds (1 WEEK) */
#define HACKHASH_EXPIRYTIME                     10      /* hash expire time in seconds since creation (10 SECONDS)*/
#define HACKCACHE_EXPIRYTIME                    200     /* access expire time in seconds (5 MINUTES) */
#define TTLFOCUSMAP_MEMORY_THRESHOLD            1024    /* 1024 DESTINATIONS */
#define SESSIONTRACKMAP_MEMORY_THRESHOLD        1024    /* 1024 TCP SESSIONS */
#define TTLPROBE_RETRY_ON_UNKNOWN               600     /* schedule time on UNKNOWN TTL status (10 MINUTES) */

#endif /* SJ_DEFINES_H */
