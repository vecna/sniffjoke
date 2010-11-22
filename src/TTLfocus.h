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

enum ttlsearch_t { TTL_KNOWN = 0, TTL_BRUTALFORCE = 1, TTL_UNKNOWN = 2 };

struct ttlfocus_cache_record {
	unsigned int daddr;
	unsigned short expiring_ttl;
	unsigned short min_working_ttl;
	unsigned short synack_ttl;
	unsigned short sent_probe;
	unsigned short received_probe;
	unsigned short puppet_port;
	unsigned int rand_key;
	ttlsearch_t status;
	
	char syncopy[1500]; 	/* we need a constant size record */
	unsigned int syncopy_len;
};


class TTLFocus {
public:
	time_t access_timestamp; /* access timestamp used to decretee expiry */

	ttlsearch_t status;
	unsigned int daddr;
	unsigned short expiring_ttl;
	unsigned short min_working_ttl;
	unsigned short synack_ttl;
	unsigned short sent_probe;
	unsigned short received_probe;
	unsigned short puppet_port;
	unsigned int rand_key;
	
	vector<unsigned char> syncopy;
	
	struct timespec next_probe_time;

	TTLFocus(const Packet &);
	TTLFocus(const struct ttlfocus_cache_record &);
	void scheduleNextProbe50ms();
	void scheduleNextProbe2mins();
	bool isProbeIntervalPassed(const struct timespec &) const;

	/* utilities */
	void selflog(const char *, const char *);
	char debug_buf[LARGEBUF];
};

class TTLFocusMap : public map<const unsigned int, TTLFocus> {
public:
        void dump();
        void load();
        
        TTLFocus* add_ttlfocus(const Packet &pkt);
        TTLFocus* get_ttlfocus(unsigned int);
        void manage_expired();
};


#endif /* SJ_TTLFOCUS_H */
