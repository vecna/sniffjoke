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
 * I didn't rembemer exactly, zero window TCP packet are used for stop the 
 * communication until resume is requested
 * 
 * SOURCE: deduction, whishful thinking
 * VERIFIED IN:
 * KNOW BUGS:
 * WRITTEN IN VERSION: 0.4.0
 */

#include "Hack.h"

class fake_zero_window : public Hack
{
#define HACK_NAME	"Fake 0-window"
public:
	virtual void createHack(const Packet &orig_packet)
	{
		orig_packet.selflog(HACK_NAME, "Original packet");

		Packet* pkt = new Packet(orig_packet);

		pkt->TCPPAYLOAD_resize(0);

		pkt->tcp->syn = pkt->tcp->fin = pkt->tcp->rst = 0;
		pkt->tcp->psh = pkt->tcp->ack = 0;
		pkt->tcp->window = 0;

		pkt->position = ANY_POSITION;
		pkt->wtf = RANDOMDAMAGE;

		pkt->selflog(HACK_NAME, "Hacked packet");

		pktVector.push_back(pkt);
	}

	fake_zero_window() {
		hackName = HACK_NAME;
		hackFrequency = TIMEBASED20S;
	}

};

extern "C"  Hack* CreateHackObject() {
	return new fake_zero_window();
}

extern "C" void DeleteHackObject(Hack *who) {
	delete who;
}

extern "C" const char *versionValue() {
 	return SW_VERSION;
}
