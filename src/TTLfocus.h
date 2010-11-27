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

#ifndef SJ_TTLFOCUS_H
#define SJ_TTLFOCUS_H

#include "Utils.h"
#include "UserConf.h"
#include "Packet.h"

#include <map>
#include <vector>

#include "time.h"

using namespace std;

/* IT'S FUNDAMENTAL TO HAVE ALL THIS ENUMS VALUES AS POWERS OF TWO TO PERMIT OR MASKS */

enum ttlsearch_t { TTL_KNOWN = 0, TTL_BRUTEFORCE = 1, TTL_UNKNOWN = 2 };

class TTLFocus {
public:
	/* timing variables */
	time_t access_timestamp;		/* access timestamp used to decretee expiry */
	struct timespec next_probe_time;	/* timeout value used for ttlprobe schedule */

	/* status variables */
	ttlsearch_t status;			/* status of the traceroute */
	unsigned int rand_key;			/* random key used as try to discriminate traceroute packet */
	unsigned short puppet_port;		/* random port used with the aim to not disturbe a session */
#define PUPPET_MARGIN	10			/* margin to mantain between real dest port and puppet port
						   with the aim to not disturbe a session */
	unsigned short sent_probe;		/* number of sent probes */
	unsigned short received_probe;		/* number of received probes */
	
	/* ttl informations, results of the analysis */
	unsigned int daddr;			/* destination of the traceroute */
	unsigned short ttl_estimate;		/* hop count estimate found during ttlbruteforce;
						 *   on status KNOWN   : represents the min working ttl found
						 *   on status UNKNOWN : represents the max expired ttl found */
	unsigned short synack_ttl;		/* the value of the ttl read in the synack packet */


	Packet probe_dummy;			/* dummy ttlprobe packet generated from the packet
						   that scattered the ttlfocus creation. */

	TTLFocus(const Packet &pkt);
	TTLFocus(const struct ttlfocus_cache_record &);
	void selectPuppetPort();

	/* utilities */
	void selflog(const char *, const char *) const;
	char debug_buf[LARGEBUF];
};

class TTLFocusMap : public map<const unsigned int, TTLFocus> {
public:
        void dump(const char *);
        void load(const char *);
};

struct ttlfocus_cache_record {
	unsigned int daddr;			/* destination of the traceroute */
	unsigned short expiring_ttl;		/* the min exiping_ttl found during analysis */
	unsigned short ttl_estimate;		/* the min working ttl found during analysis */
	unsigned short synack_ttl;		/* the value of the ttl read in the synack packet */
	
	unsigned char probe_dummy[40];		/* dummy ttlprobe packet generated from the packet
						   that scattered the ttlfocus creation.
						   the packet size is always 40 bytes long,
						   (sizeof(struct iphdr) + sizeof(struct tcphdr)) */
};

#endif /* SJ_TTLFOCUS_H */
