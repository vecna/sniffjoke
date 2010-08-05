#include "SessionTrackList.h"
#include "SjUtils.h"

#include <cstdlib>
#include <arpa/inet.h>

SessionTrackList::SessionTrackList()
{
    front = back = NULL;
}

SessionTrackList::~SessionTrackList()
{
    SessionTrack *tmp = get(false);
    while(tmp != NULL) {
        delete tmp;
        tmp = get(true);
    }
}

void SessionTrackList::insert(SessionTrack* sessiontrack)
{
    if(front == NULL) {
        sessiontrack->prev = NULL;
        sessiontrack->next = NULL;
        front = back = sessiontrack;
    } else {
        sessiontrack->prev = back;
        sessiontrack->next = NULL;
        back->next = sessiontrack;
        back = sessiontrack;
    }
}

void SessionTrackList::remove(const SessionTrack* sessiontrack)
{
    bool found = false;
    
    if(front == sessiontrack && back == sessiontrack) {
        front = back = NULL;
        found = true;    
    } else if(front == sessiontrack) {
        front = front->next;
        front->prev = NULL;
        found = true;
    } else if (back == sessiontrack) {
        back = back->prev;
        back->next = NULL;
        found = true;
    }

    if(!found) {
        sessiontrack->prev->next = sessiontrack->next;
        sessiontrack->next->prev = sessiontrack->prev;
    }
    
    return;
}

void SessionTrackList::drop(SessionTrack* sessiontrack)
{
    remove(sessiontrack);
    delete sessiontrack;
}

SessionTrack* SessionTrackList::get(bool must_continue)
{
    static SessionTrack *tmp;
    SessionTrack *ret;

    if (!must_continue) {
        tmp = front;
    }
    
    while(tmp != NULL) {
        ret = tmp;
        tmp = tmp->next;
        return ret;
    }
        
    return NULL;
}

/* 
 * get is used whenever you need a SessionTrack, this struct is used
 * as reference for each conntrack with the same distination address. every session
 * had access in the same SessionTrack.
 * 
 * in SessionTrack are keep the informations for ttl bruteforcing
 */
SessionTrack* SessionTrackList::get( unsigned int daddr, unsigned short sport, unsigned short dport )
{
    SessionTrack *tmp = get(false);
    while(tmp != NULL) {
        if(tmp->daddr == daddr && tmp->sport == sport && tmp->dport == dport)
            return tmp;
        tmp = get(true);
    }
    return NULL;
}


/* get( Packet *pkt ) must return a session;
 * if a session is not found, a new one is created */
SessionTrack* SessionTrackList::get( const Packet *pkt )
{
    return get(pkt->ip->daddr, pkt->tcp->source, pkt->tcp->dest);
}

/* clear_session: clear a session in two step, the first RST/FIN set shutdown 
 * variable to true, the second close finally.
 */
void SessionTrackList::clear_session( SessionTrack *sessiontrack ) 
{
    if(sessiontrack->shutdown == false) {
        internal_log(NULL, DEBUG_LEVEL,
                    "SHUTDOWN sexion sport %d dport %d daddr %u",
                    ntohs(sessiontrack->sport), ntohs(sessiontrack->dport), sessiontrack->daddr
        );
        sessiontrack->shutdown = true;
    } else {
        internal_log(NULL, DEBUG_LEVEL,
                    "Removing session: local:%d -> %s:%d TTL exp %d wrk %d #%d", 
                    ntohs(sessiontrack->sport), 
                    inet_ntoa( *((struct in_addr *)&sessiontrack->daddr) ) ,
                    ntohs(sessiontrack->dport),
                    sessiontrack->tf->expiring_ttl,
                    sessiontrack->tf->min_working_ttl,
                    sessiontrack->packet_number
        );
        remove(sessiontrack);
    }
}
