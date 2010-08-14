#include "SessionTrackList.h"
#include "SjUtils.h"

#include <arpa/inet.h>

SessionTrack* SessionTrackList::get(bool must_continue)
{
	static list<SessionTrack>::iterator i = begin();
	
	if (!must_continue)
		i = begin();
	
	if (i++ != end())
		return &(*i);

	return NULL;
}

SessionTrack* SessionTrackList::get(unsigned int daddr, unsigned short sport, unsigned short dport)
{
	for (list<SessionTrack>::iterator i = begin(); i != end(); i++) {
		if (i->daddr == daddr && i->sport == sport && i->dport == dport) {
			return &(*i);
		}
	}
	return NULL;
}


SessionTrack* SessionTrackList::get(const Packet *pkt)
{
	return get(pkt->ip->daddr, pkt->tcp->source, pkt->tcp->dest);
}

/* clear_session: clear a session in two step, the first RST/FIN set shutdown 
 * variable to true, the second close finally.
 */
void SessionTrackList::clear_session(SessionTrack* st) 
{
	if (st->shutdown == false) {
		internal_log(NULL, DEBUG_LEVEL,
					"SHUTDOWN sexion sport %d dport %d daddr %u",
					ntohs(st->sport), ntohs(st->dport), st->daddr
		);
		st->shutdown = true;
	} else {
		internal_log(NULL, DEBUG_LEVEL,
					"Removing session: local:%d . %s:%d #%d", 
					ntohs(st->sport), 
					inet_ntoa(*((struct in_addr *)&st->daddr)) ,
					ntohs(st->dport),
					st->packet_number
		);
		remove(*st);
	}
}
