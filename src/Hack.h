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

#ifndef SJ_HACK_H
#define SJ_HACK_H

#include "Packet.h"

#include <vector>

using namespace std;

/* 
 * HackPacket - pure virtual methods 
 *
 * Following this howto: http://www.faqs.org/docs/Linux-mini/C++-dlopen.html
 * We understood how to do a plugin and load it.
 * HackPacket classes are implemented as external modules and the programmer
 * shoulds implement Condition and createHack, constructor and distructor methods.
 *
 * At the end of every plugin code, it's is required to export two "C" symbols,
 * pointing to the constructor and the destructor method.
 *
 */

/* the Frequency meaning is explained in http://www.delirandom.net/sniffjoke/plugin */
enum Frequency { FREQUENCYUNASSIGNED = 0, RARE = 1, COMMON = 2, PACKETS10PEEK = 3, PACKETS30PEEK = 4,
		 TIMEBASED5S = 5, TIMEBASED20S = 6, STARTPEEK = 7, LONGPEEK = 8 };

class Hack {
public:
	const char *hackName;		/* hack name as const string */
	Frequency hackFrequency;	/* hack frequency */
	bool removeOrigPkt;		/* boolean to be set true if the hack
					   needs to remove the original packet */

	vector<Packet*> pktVector;	/* std vector of Packet* used for created hack packets */

	Hack() : hackName(NULL), hackFrequency(FREQUENCYUNASSIGNED), removeOrigPkt(false) {};
	virtual bool Condition(const Packet &) { return true; };
	virtual void createHack(const Packet &) = 0;
};

#endif /* SJ_HACK_H */
