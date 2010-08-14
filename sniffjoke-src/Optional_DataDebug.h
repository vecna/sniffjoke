#ifndef SJ_OPTIONAL_DATADEBUG_H
#define SJ_OPTIONAL_DATADEBUG_H

#include "PacketQueue.h"
#include "SessionTrackList.h"
#include "TTLFocusList.h"

#include <cstdio>

#define SESSION_FILE_DEBUG	"/tmp/datadump/session.log"
#define PACKET_FILE_DEBUG	"/tmp/datadump/packet.log"
#define TTL_FILE_DEBUG		"/tmp/datadump/ttl.log"

class DataDebug 
{
private:
	FILE *Session_f, *Packet_f, *TTL_f;
public:
	DataDebug();
	~DataDebug();

	void Dump_Packet(PacketQueue *);
	void Dump_Session(SessionTrackList *);
	void Dump_TTL(TTLFocusList *);

	/* "Session", "Packet", "TTL" */
	void InfoMsg(const char *, const char *, ...);
};

#endif /* SJ_OPTIONAL_DATADEBUG_H */
