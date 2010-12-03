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

#include "TTLfocus.h"

#include <cerrno>
#include <cstdlib>
#include <cstring>

#include <unistd.h>
#include <arpa/inet.h>

TTLFocus::TTLFocus(const Packet &pkt) :
	access_timestamp(0),
	status(TTL_BRUTEFORCE),
	rand_key(random()),
	puppet_port(0),
	sent_probe(0),
	received_probe(0),
	daddr(pkt.ip->daddr),
        ttl_estimate(0xff),
	synack_ttl(0),
	probe_dummy(pkt)
{
	probe_dummy.IPHDR_resize(sizeof(struct iphdr));
	probe_dummy.TCPHDR_resize(sizeof(struct tcphdr));
	probe_dummy.TCPPAYLOAD_resize(0);
	probe_dummy.tcp->fin = 0;
	probe_dummy.tcp->syn = 1;
	probe_dummy.tcp->rst = 0;
	probe_dummy.tcp->psh = 0;
	probe_dummy.tcp->ack = 0;
	probe_dummy.tcp->urg = 0;
	probe_dummy.tcp->res1 = 0;
	probe_dummy.tcp->res2 = 0;
	
	selectPuppetPort();
	
	/* setting n_p_t to sj_clock we force update on next check */
	next_probe_time = sj_clock;
	
	selflog(__func__, NULL);
}

TTLFocus::TTLFocus(const struct ttlfocus_cache_record& cpy) :
	access_timestamp(0),
	status(TTL_KNOWN),
	rand_key(random()),
	puppet_port(0),
	sent_probe(0),
	received_probe(0),
	daddr(cpy.daddr),
	ttl_estimate(cpy.ttl_estimate),
	synack_ttl(cpy.synack_ttl),
	probe_dummy(cpy.probe_dummy, sizeof(cpy.probe_dummy))
{
	selectPuppetPort();	

	/* setting n_p_t to sj_clock we force update on next check */
	next_probe_time = sj_clock;

	selectPuppetPort();

	selflog(__func__, NULL);
}

TTLFocus::~TTLFocus()
{
	selflog(__func__, NULL);
}

void TTLFocus::selectPuppetPort()
{
	uint16_t realport = probe_dummy.tcp->source;
	puppet_port = (realport + random()) % 32767 + 1;
        if(puppet_port > realport - PUPPET_MARGIN
	&& puppet_port < realport + PUPPET_MARGIN)
		puppet_port = (puppet_port + (random() % 2) ? -PUPPET_MARGIN : +PUPPET_MARGIN) % 32767 + 1;
}

void TTLFocus::selflog(const char *func, const char *umsg) const
{
	if(debug.level() == SUPPRESS_LOG)
		return;
		
	const char *status_name;

	switch(status) {
		case TTL_KNOWN: status_name = "TTL known"; break;
		case TTL_BRUTEFORCE: status_name = "BRUTEFORCE running"; break;
		case TTL_UNKNOWN: status_name = "TTL UNKNOWN"; break;
		default: status_name = "badly unset TTL status"; break;
	}

	debug.log(SESSION_DEBUG, 
		"%s (%s) [%s] m_sent %d, m_recv %d ttl_estimate %u synackttl %u [%s]",
		func, inet_ntoa(*((struct in_addr *)&(daddr))), status_name, sent_probe, received_probe, ttl_estimate, synack_ttl, umsg
	);

	memset((void*)debug_buf, 0x00, sizeof(debug_buf));
}

TTLFocusMap::TTLFocusMap() {
	debug.log(VERBOSE_LEVEL, __func__);	
}

TTLFocusMap::~TTLFocusMap() {
	debug.log(VERBOSE_LEVEL, __func__);	
	for(TTLFocusMap::iterator it = begin(); it != end();) {
		delete &(*it->second);
		erase(it++);
	}
}

/* cycles on map and delete expired records */
void TTLFocusMap::manage_expired()
{
	for(TTLFocusMap::iterator it = begin(); it != end();) {
		if((*it).second->access_timestamp + TTLFOCUS_EXPIRYTIME < sj_clock.tv_sec) {
			delete &(*it->second);
			erase(it++);
		} else {
			++it;
		}
	}
}

void TTLFocusMap::load(const char* dumpfile)
{
	uint32_t records_num = 0;
	struct ttlfocus_cache_record tmp;
	int ret;
	
	debug.log(ALL_LEVEL, "loading ttlfocusmap from %s",  dumpfile);
	
	FILE *loadfd = fopen(dumpfile, "r");
	if(loadfd == NULL) {
		debug.log(ALL_LEVEL, "unable to access %s: sniffjoke will start without a ttl cache", dumpfile);
        	return;
        }

	while((ret = fread(&tmp, sizeof(struct ttlfocus_cache_record), 1, loadfd)) == 1) {
		records_num++;
		TTLFocus *ttlfocus = new TTLFocus(tmp);
		insert(pair<const uint32_t, TTLFocus*>(ttlfocus->daddr, ttlfocus));
	}

	fclose(loadfd);

	if(ret != 0) {
		unlink(TTLFOCUSCACHE_FILE);
		debug.log(ALL_LEVEL, "unable to read ttlfocus from %s: %s",
			dumpfile, strerror(errno)
		);
		SJ_RUNTIME_EXCEPTION("");
	}
	debug.log(ALL_LEVEL, "ttlfocusmap load completed: %u records loaded", records_num);
}


void TTLFocusMap::dump(const char* dumpfile)
{
	uint32_t records_num = 0;
	struct ttlfocus_cache_record cache_record;

	debug.log(ALL_LEVEL, "dumping ttlfocusmap to %s",  dumpfile);

	FILE *dumpfd = fopen(dumpfile, "w");
        if(dumpfd == NULL) {
                debug.log(ALL_LEVEL, "unable to access %s: sniffjoke will not dump ttl cache", dumpfile);
                return;
        }

	for (TTLFocusMap::iterator it = begin(); it != end(); ++it) {

		TTLFocus *tmp = it->second;

		/* we saves only with TTL_KNOWN status */
		if(tmp->status != TTL_KNOWN)
			continue;

		cache_record.daddr = tmp->daddr;
		cache_record.ttl_estimate = tmp->ttl_estimate;
		cache_record.synack_ttl = tmp->synack_ttl;

		/*
		 * copy the probe_dummy.pbuf vector into the cache record;
		 * a ttlprobe packet is always 40 bytes (min iphdr + min tcphdr),
		 * ipopts, tcpopts, and payload are stripped of on creation
		 */
		memcpy(cache_record.probe_dummy, &(tmp->probe_dummy.pbuf[0]), 40);
		
		if(fwrite(&cache_record, sizeof(struct ttlfocus_cache_record), 1, dumpfd) != 1)
		{
			fclose(dumpfd);
			unlink(dumpfile);
			debug.log(ALL_LEVEL, "unable to write ttlfocus to %s: %s",
				dumpfile, strerror(errno)
			);
			return;
		}
		
		++records_num;
	}
	fclose(dumpfd);

	debug.log(ALL_LEVEL, "ttlfocusmap dump completed: %u records dumped", records_num);
}
