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

SessionTrack::SessionTrack(const Packet &pkt) :
	access_timestamp(time(NULL)),
	daddr(pkt.ip->daddr),
	sport(pkt.tcp->source),
	dport(pkt.tcp->dest),
	isn(pkt.tcp->seq),
	packet_number(1),
	shutdown(false)
{}

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

void SessionTrack::selflog(const char *func, const char *lmsg) 
{
	debug.log(SESSION_DEBUG, "%s sport %d saddr %s dport %u, ISN %x shutdown %s #pkt %d: [%s]",
		func, ntohs(sport), 
		inet_ntoa(*((struct in_addr *)&daddr)),
                ntohl(isn),
		ntohs(dport), 
		shutdown ? "TRUE" : "FALSE",
		packet_number, lmsg
	);
}

SessionTrack* SessionTrackMap::add_sessiontrack(const Packet &pkt)
{
	SessionTrackKey key = {pkt.ip->daddr, pkt.tcp->source, pkt.tcp->dest};
	SessionTrack *sessiontrack = &(insert(pair<SessionTrackKey, SessionTrack>(key, pkt)).first->second);
	sessiontrack->access_timestamp = time(NULL);
	return sessiontrack;
}

SessionTrack* SessionTrackMap::get_sessiontrack(const Packet &pkt, bool direct)
{
	SessionTrackKey key;
	if(direct) {
		key.daddr = pkt.ip->daddr;
		key.sport = pkt.tcp->source;
		key.dport = pkt.tcp->dest;
	} else {
		key.daddr = pkt.ip->saddr;
		key.sport = pkt.tcp->dest;
		key.dport = pkt.tcp->source;
	}

	SessionTrackMap::iterator it = find(key);		
	if(it != end()) {
		(it->second).access_timestamp = time(NULL);
		return &(it->second);
	} else {
		return NULL;
	}
}


void SessionTrackMap::clear_sessiontrack(const Packet &pkt)
{
	/* 
	 * clear_session don't remove conntrack immediatly, at the first call
	 * set the "shutdown" bool variable, at the second clear it, this
	 * because of double FIN-ACK and RST-ACK happening between both hosts.
	 */
	SessionTrackKey key = {pkt.ip->saddr, pkt.tcp->dest, pkt.tcp->source};
	SessionTrackMap::iterator it = find(key);

	if (it != end()) {
		SessionTrack &st = it->second;
		if (st.shutdown == false) {
			st.selflog(__func__, "shutdown false set to be true");
			st.shutdown = true;
		} else {
			st.selflog(__func__, "shutdown true, deleting session");
			erase(it);
		}
	}
}

void SessionTrackMap::manage_expired()
{
	time_t now = time(NULL);
	for(SessionTrackMap::iterator it = begin(); it != end();) {
		if((*it).second.access_timestamp + SESSIONTRACK_EXPIRETIME < now)
			erase(it++);
		else
			it++;
	}
}
