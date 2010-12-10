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
 * we understood how to do a plugin and load it.
 * HackPacket classes are implemented as external modules and the programmer
 * shoulds implement Condition and createHack, constructor and distructor methods.
 *
 * At the end of every plugin code, it's is required to export two "C" symbols,
 * pointing to the constructor and the destructor method.
 *
 */

/* the Frequency meaning is explained in http://www.delirandom.net/sniffjoke/plugin */
enum Frequency { RARE = 1, COMMON = 2, ALWAYS = 3, PACKETS10PEEK = 4, PACKETS30PEEK = 5,
		 TIMEBASED5S = 6, TIMEBASED20S = 7, STARTPEEK = 8, LONGPEEK = 9 };

class Hack {
public:
	const char *hackName;		/* hack name as const string */
	const Frequency hackFrequency;	/* hack frequency */
	const bool removeOrigPkt;	/* boolean to be set true if the hack
					   needs to remove the original packet */

	vector<Packet*> pktVector;	/* std vector of Packet* used for created hack packets */


	Hack(const char* hackName, Frequency hackFrequency, bool removeOrigPkt = false) :
		hackName(hackName),
		hackFrequency(hackFrequency),
		removeOrigPkt(removeOrigPkt)
	{};
	virtual bool Condition(const Packet &) { return true; };
	virtual void createHack(const Packet &) = 0;
};
#endif /* SJ_HACK_H */
