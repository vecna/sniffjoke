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

#include "SessionTrack.h"

#include <algorithm>
#include <memory>

using namespace std;

SessionTrack::SessionTrack(const Packet &pkt) :
	access_timestamp(0),
	daddr(pkt.ip->daddr),
	sport(pkt.tcp->source),
	dport(pkt.tcp->dest),
	packet_number(0)
{
	selflog(__func__, NULL);
}

SessionTrack::~SessionTrack()
{
	selflog(__func__, NULL);
}

bool SessionTrackKey::operator<(SessionTrackKey comp) const
{
	if (daddr < comp.daddr) {
		return true;
	} else if (daddr > comp.daddr) {
		return false;
	} else {
		if (sport < comp.sport) {
			return true;
		} else if (sport > comp.sport) {
			return false;
		} else {
			if (dport < comp.dport)
				return true;
			else
				return false;
		}
	}
}

void SessionTrack::selflog(const char *func, const char *lmsg) const
{
	if (debug.level() == SUPPRESS_LOG)
		return;

	debug.log(SESSION_DEBUG, "%s sport %d saddr %s dport %u, #pkt %d: [%s]",
		func, ntohs(sport), 
		inet_ntoa(*((struct in_addr *)&daddr)),
		ntohs(dport), 
		packet_number, lmsg
	);
}

SessionTrackMap::SessionTrackMap() {
	debug.log(VERBOSE_LEVEL, __func__);	
}

SessionTrackMap::~SessionTrackMap() {
	debug.log(VERBOSE_LEVEL, __func__);
	for(SessionTrackMap::iterator it = begin(); it != end();) {
		delete &(*it->second);
		erase(it++);
	}
}

/* return a sessiontrack given a packet; return a new sessiontrack if no one exists */
SessionTrack& SessionTrackMap::getSessionTrack(const Packet &pkt)
{
	SessionTrack *sessiontrack;
	
	/* create map key */
	const SessionTrackKey key = { pkt.ip->daddr, pkt.tcp->source, pkt.tcp->dest };
	
	/* check if the key it's already present */
	SessionTrackMap::iterator it = find(key);
	if (it != end()) /* on hit: return the sessiontrack object. */
		sessiontrack = it->second;
	else { /* on miss: create a new sessiontrack and insert it into the map */
		sessiontrack = insert(pair<const SessionTrackKey, SessionTrack*>(key, new SessionTrack(pkt))).first->second;
	}
		
	/* update access timestamp using global clock */
	sessiontrack->access_timestamp = sj_clock.tv_sec;

	return *sessiontrack;
}

struct sessiontrack_timestamp_comparison {
	bool operator() (SessionTrack *i, SessionTrack *j)
	{
		return ( i->access_timestamp < j->access_timestamp );
	}
} sessiontrackTimestampComparison;

void SessionTrackMap::manage()
{
	if (!(sj_clock.tv_sec % SESSIONTRACKMAP_MANAGE_ROUTINE_TIMER)) {
		for(SessionTrackMap::iterator it = begin(); it != end();) {
			if ((*it).second->access_timestamp + SESSIONTRACK_EXPIRYTIME < sj_clock.tv_sec) {
				delete &(*it->second);
				erase(it++);
			} else {
				it++;
			}
		}
	}

	uint32_t map_size = size();
	if (map_size > SESSIONTRACKMAP_MEMORY_THRESHOLD) {
		SessionTrack** tmp = new SessionTrack*[map_size];

		uint32_t index = 0;
 		for(SessionTrackMap::iterator it = begin(); it != end(); ++it)
			tmp[index++] = it->second;

		clear();

		sort(tmp, tmp+map_size, sessiontrackTimestampComparison);

		index = 0;
		do {
			delete tmp[index];
		} while( index++ != SESSIONTRACKMAP_MEMORY_THRESHOLD / 2 );

		do {
			const SessionTrackKey key = { tmp[index]->daddr, tmp[index]->sport, tmp[index]->dport };
			insert(pair<SessionTrackKey, SessionTrack *>(key, tmp[index]));
		} while( index++ != SESSIONTRACKMAP_MEMORY_THRESHOLD);

		delete[] tmp;
	}
}
