#ifndef SJ_SESSIONTRACKLIST_H
#define SJ_SESSIONTRACKLIST_H

#include "SessionTrack.h"

class SessionTrackList {
public:
    SessionTrack *front;
    SessionTrack *back;

    SessionTrackList();
    ~SessionTrackList();
    void insert(SessionTrack* SessionTrack);
    void remove(const SessionTrack* SessionTrack);
    void drop(SessionTrack* SessionTrack);
    SessionTrack* get( bool );
    SessionTrack* get( unsigned int, unsigned short , unsigned short );
    SessionTrack* get( const Packet * );
    void clear_session( SessionTrack * );
};

#endif /* SJ_SESSIONTRACKLIST_H */
