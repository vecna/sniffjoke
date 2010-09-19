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
#include "sj_ttlfocus.h"
#include "sj_defines.h"
#include "sj_utils.h"

#include <cerrno>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>

TTLFocus::TTLFocus(unsigned int destip) :
	daddr(destip),
	min_working_ttl(0xff),
	expiring_ttl(0),
	sent_probe(0),
	received_probe(0),
	puppet_port(htons((random() % 15000) + 1100)),
	rand_key(random()),
	status(TTL_BRUTALFORCE)
{}

TTLFocus::TTLFocus(const TTLFocus& cpy) :
	daddr(cpy.daddr),
	min_working_ttl(cpy.min_working_ttl),
	expiring_ttl(cpy.expiring_ttl),
	sent_probe(cpy.sent_probe),
	received_probe(cpy.received_probe),
	puppet_port(cpy.puppet_port),
	rand_key(cpy.rand_key),
	status(cpy.status)
{}

TTLFocus::TTLFocus(const struct ttlfocus_cache_record& cpy) :
	daddr(cpy.daddr),
	min_working_ttl(cpy.min_working_ttl),
	expiring_ttl(cpy.expiring_ttl),
	sent_probe(cpy.sent_probe),
	received_probe(cpy.received_probe),
	puppet_port(cpy.puppet_port),
	rand_key(cpy.rand_key),
	status(cpy.status)
{}

TTLFocusMap::TTLFocusMap() {
	load();
}
TTLFocusMap::~TTLFocusMap() {
	dump();
}

void TTLFocusMap::load() {
	FILE *loadfd;
	int i = 0;
	int ret;
	struct ttlfocus_cache_record tmp;

	internal_log(NULL, VERBOSE_LEVEL, "loading ttlfocusmap from %s",  TTLFOCUSMAP_FILE);
	
	loadfd = fopen(TTLFOCUSMAP_FILE, "r");
	if(loadfd == NULL) {
		internal_log(NULL, ALL_LEVEL, "unable to access %s: sniffjoke will start without a ttl cache", TTLFOCUSMAP_FILE);
        	return;
        }

	while( (ret = fread(&tmp, sizeof(struct ttlfocus_cache_record), 1, loadfd)) == 1 ) {
		i++;
		TTLFocus *ttlfocus = new TTLFocus(tmp);
		insert(pair<int, TTLFocus>(ttlfocus->daddr, *ttlfocus));
	}

	fclose(loadfd);

	if(ret != 0) {
		unlink(TTLFOCUSMAP_FILE);
		internal_log(NULL, ALL_LEVEL, "unable to read ttlfocus from %s: %s",
			TTLFOCUSMAP_FILE, strerror(errno)
		);
		check_call_ret("reading ttlfocus file", errno, (ret - 1), false);
	}
	internal_log(NULL, VERBOSE_LEVEL, "ttlfocusmap load completed: %d records loaded", i);
}


void TTLFocusMap::dump() {
	FILE *dumpfd;
	int i = 0;
	int ret;
	TTLFocus* tmp;
	struct ttlfocus_cache_record cache_record;

	internal_log(NULL, VERBOSE_LEVEL, "dumping ttlfocusmap to %s",  TTLFOCUSMAP_FILE);

	dumpfd = fopen(TTLFOCUSMAP_FILE, "w");
        if(dumpfd == NULL) {
                internal_log(NULL, ALL_LEVEL, "unable to access %s: sniffjoke will not dump ttl cache", TTLFOCUSMAP_FILE);
                return;
        }


	for ( TTLFocusMap::iterator it = this->begin(); it != this->end(); it++ ) {
		i++;
		tmp = &(it->second);
		cache_record.daddr = tmp->daddr;
		cache_record.expiring_ttl = tmp->expiring_ttl;
		cache_record.min_working_ttl = tmp->min_working_ttl;
		cache_record.sent_probe = tmp->sent_probe;
		cache_record.received_probe = tmp->received_probe;
		cache_record.puppet_port = tmp->puppet_port;
		cache_record.rand_key = tmp->rand_key;
		cache_record.status = tmp->status;

		ret = fwrite(&cache_record, sizeof(struct ttlfocus_cache_record), 1, dumpfd);
		if(ret != 1)
		{
			fclose(dumpfd);
			unlink(TTLFOCUSMAP_FILE);
			internal_log(NULL, ALL_LEVEL, "unable to write ttlfocus to %s: %s",
				TTLFOCUSMAP_FILE, strerror(errno)
			);
			check_call_ret("writing ttlfocus file", errno, (ret - 1), false);
			return;
		}
	}
	fclose(dumpfd);

	internal_log(NULL, VERBOSE_LEVEL, "ttlfocusmap dump completed: %d records dumped", i);
}
