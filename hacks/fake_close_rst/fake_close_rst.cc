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
 * fake close is used because a sniffer could read a FIN like a session closing
 * tcp-flag, and stop the session monitoring/reassembly.
 *
 * SOURCE: phrack, deduction, 
 * VERIFIED IN:
 * KNOW BUGS: fastweb network (italian wire provider), should not support this hack 
 * 	      because the HAG close the session at the first valid RST exiting
 * 	      from your box.
 */

#include "Packet.h"

class fake_close_rst : public HackPacket
{
private:
public:
	virtual Packet *createHack(Packet &orig_packet)
	{
		Packet* ret = new Packet(orig_packet);
		
		const int original_size = ret->orig_pktlen - (ret->ip->ihl * 4) - (ret->tcp->doff * 4);

		ret->resizePayload(0);

		ret->ip->id = htons(ntohs(ret->ip->id) + (random() % 10));

		ret->tcp->psh = 0;

		ret->tcp->rst = 1;
	
		ret->tcp->seq = htonl(ntohl(ret->tcp->seq) - original_size + 1);

		ret->fillRandomPayload();

		ret->position = ANTICIPATION;

		return ret;
	}

	virtual bool Condition(const Packet &orig_packet)
	{
		return (orig_packet.tcp->ack != 0);
	}

	fake_close_rst() {
		hackname = "fake_close_rst";
		hack_frequency = 5;
		prescription_probability = 98;
	}
};

extern "C"  HackPacket* CreateHackObject() {
	return new fake_close_rst;
}

extern "C" void DeleteHackObject(HackPacket *who) {
	delete who;
}
