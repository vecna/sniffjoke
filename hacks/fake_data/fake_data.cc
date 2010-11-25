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

/*
 * HACK COMMENT:, every hacks require intensive comments because should cause 
 * malfunction, or KILL THE INTERNET :)
 * 
 * the hacks inject two packet (maked as invalid, with TTL expiring or bad
 * checksum) with a fake data, of the same length of the original packet,
 * one BEFORE and one AFTER the real packet. this cause that the sniffer (that 
 * eventually confirm the readed data when the data was acknowledged), had
 * memorized the first packet or the last only (because they share the same
 * sequence number). the reassembled flow appear override bye the data here
 * injected. should be the leverage for an applicative injection (like a 
 * fake mail instead of the real mail, etc...)
 * 
 * SOURCE: deduction, analysis of libnids
 * VERIFIED IN:
 * KNOW BUGS:
 * WRITTEN IN VERSION: 0.4.0
 */

#include "Hack.h"

class fake_data : public Hack
{
#define HACK_NAME "Fake data"
public:
	virtual void createHack(const Packet &orig_packet)
	{
		orig_packet.selflog(HACK_NAME, "Original packet");

		Packet* pkt1 = new Packet(orig_packet);
		Packet* pkt2 = new Packet(orig_packet);
		pkt1->TCPPAYLOAD_fillrandom();
		pkt2->TCPPAYLOAD_fillrandom();
		
		pkt1->position = ANTICIPATION;
		pkt2->position = POSTICIPATION;
		pkt1->wtf = RANDOMDAMAGE;
		pkt2->wtf = RANDOMDAMAGE;

		pkt1->selflog(HACK_NAME, "Hacked packet");
		pkt2->selflog(HACK_NAME, "Hacked packet");

		pktVector.push_back(pkt1);
		pktVector.push_back(pkt2);
	}

	virtual bool Condition(const Packet &orig_packet)
	{
		return (orig_packet.payload != NULL);		
	}

	fake_data() {
		hackName = HACK_NAME;
		hackFrequency = COMMON;
	}
};

extern "C"  Hack* CreateHackObject() {
	return new fake_data();
}

extern "C" void DeleteHackObject(Hack *who) {
	delete who;
}
