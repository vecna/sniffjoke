#ifndef SJ_SESSIONTRACKLIST_H
#define SJ_SESSIONTRACKLIST_H

#include "SessionTrack.h"

#include <list>
using namespace std;

class SessionTrackList : public list<SessionTrack> {
public:
	SessionTrack* get( unsigned int, unsigned short , unsigned short );
	SessionTrack* get( const Packet* );
	void clear_session( SessionTrack* );
};

#endif /* SJ_SESSIONTRACKLIST_H */
