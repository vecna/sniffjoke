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
 * fake_data_anticipation and fake_data_posticipation
 * are both the same hack, and need to be used together, anyway for 
 * design pourpose, every injected packet require a dedicated 
 * function.
 *
 * the hacks inject a packet (maked as invalid, with TTL expiring or bad
 * checksum) with a fake data, of the same length of the original packet,
 * BEFORE and AFTER the real packet. this cause that the sniffer (that 
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

#include "Packet.h"

class fake_data_anticipation : public HackPacket
{
private:
public:
	virtual Packet *createHack(Packet &orig_packet)
	{
		Packet* ret = new Packet(orig_packet);
		ret->fillRandomPayload();

		ret->position = ANTICIPATION;

		return ret;
	}

	virtual bool Condition(const Packet &orig_packet)
	{
		return (orig_packet.payload != NULL);		
	}

	fake_data_anticipation(int plugin_index) {
		track_index =plugin_index;
		hackName = "Fake data anticipation";
		hack_frequency = 50;
	}
};

extern "C"  HackPacket* CreateHackObject(int plugin_tracked_index) {
	return new fake_data_anticipation(plugin_tracked_index);
}

extern "C" void DeleteHackObject(HackPacket *who) {
	delete who;
}
