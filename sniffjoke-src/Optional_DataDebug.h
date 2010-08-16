#ifndef SJ_OPTIONAL_DATADEBUG_H
#define SJ_OPTIONAL_DATADEBUG_H

#include "PacketQueue.h"
#include "SessionTrack.h"
#include "TTLFocus.h"

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

	void Dump_Packet(PacketQueue &);
	void Dump_Session(SessionTrackMap &);
	void Dump_TTL(TTLFocusMap &);

	/* "Session", "Packet", "TTL" */
	void InfoMsg(const char *, const char *, ...);
};

#endif /* SJ_OPTIONAL_DATADEBUG_H */
