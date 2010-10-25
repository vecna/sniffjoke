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
#ifndef SJ_HACKPKTS_H
#define SJ_HACKPKTS_H

#include "Packet.h"
#if 0
/* FIXME questo file dovrebbe chiamarsi: default-hacks.h */
class FakeDataPosticipation : public HackPacket {
public:
	virtual bool Condition(Packet &); //  { return false; };
	virtual Packet *createHack(Packet &); //  { return NULL; };
	FakeDataPosticipation(const Packet &);
};

class FakeDataAnticipation : public HackPacket {
/*
public:
	bool Condition(Packet &);
	Packet *createHack(Packet &);
	FakeDataAnticipation(const Packet &);
	~FakeDataAnticipation();
*/
};
#endif

#endif /* SJ_HACKPKTS_H */
