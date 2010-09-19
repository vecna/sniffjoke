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
#ifndef SJ_OPTIONAL_DATADEBUG_H
#define SJ_OPTIONAL_DATADEBUG_H

#include "sj_packetqueue.h"
#include "sj_sessiontrack.h"
#include "sj_ttlfocus.h"

#include <cstdio>

#define SESSION_FILE_DEBUG	"datadump/session.log"
#define PACKET_FILE_DEBUG	"datadump/packet.log"
#define TTL_FILE_DEBUG		"datadump/ttl.log"

class DataDebug 
{
private:
	FILE *Session_f, *Packet_f, *TTL_f;
public:
	DataDebug(void);
	~DataDebug(void);

	void Dump_Packet(PacketQueue &);
	void Dump_Session(SessionTrackMap &);
	void Dump_TTL(TTLFocusMap &);

	/* "Session", "Packet", "TTL" */
	void InfoMsg(const char *, const char *, ...);
};

#endif /* SJ_OPTIONAL_DATADEBUG_H */
