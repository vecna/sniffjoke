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
 
/*
 * this is the define value used in sniffjoke. if you are making porting of sniffjoke
 * for a distribution, this is your file
 */

#ifndef SJ_DEFINES_H
#define SJ_DEFINES_H

#include "config.h"

#define SW_NAME                         "SniffJoke"
#define SW_VERSION                      "0.4 beta 1"

/* Sniffjoke defaults config values */
#define DROP_USER                       "sniffjoke"
#define DROP_GROUP                      "sniffjoke"
#define MAGICVAL			0xADECADDE
#define CHROOT_DIR			INSTALL_STATEDIR
#define PLUGINSENABLER			INSTALL_SYSCONFDIR"plugins_enabled.txt"
#define MAXPLUGINS			32
#define CONF_FILE 			"sjconf.bin"     		//relative to chroot_dir
#define LOGFILE                        	"sniffjoke.log"                 //relative to chroot_dir
#define SUFFIX_LF_PACKETS               ".packets"
#define SUFFIX_LF_SESSIONS              ".sessions"
#define DEFAULT_DEBUG_LEVEL             2
#define DEFAULT_MAX_TTLPROBE		35

#define SJ_PIDFILE			"/var/run/sniffjoke.pid"

/* those are used under chroot */
#define SJ_SERVICE_UNIXSOCK		"sniffjoke_service" 
#define SJ_CLIENT_UNIXSOCK		"sniffjoke_client"

/* TTL related define */
#define TTLFOCUSCACHE_FILE		"ttlfocus.bin"

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
