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
 * KNOW BUGS:
 */

#include "Packet.h"
#include "Utils.h"

class fake_close_fin : public HackPacket
{
#define HACK_NAME	"Fake Fin"
public:
	virtual Packet *createHack(Packet &orig_packet)
	{
		Packet* ret = new Packet(orig_packet);
		
		const int original_size = ret->orig_pktlen - (ret->ip->ihl * 4) - (ret->tcp->doff * 4);
		orig_packet.selflog(HACK_NAME, "Original packet");

		ret->resizePayload(0);
		ret->fillRandomPayload();

		ret->ip->id = htons(ntohs(ret->ip->id) + (random() % 10));
		ret->tcp->seq = htonl(ntohl(ret->tcp->seq) - original_size + 1);

		ret->tcp->psh = 0;
		ret->tcp->fin = 1;

		ret->position = ANTICIPATION;
		ret->wtf = RANDOMDAMAGE;
		ret->proto = TCP;

		ret->selflog(HACK_NAME, "Hacked packet");
		return ret;
	}

	virtual bool Condition(const Packet &orig_packet)
	{
		return (orig_packet.tcp->ack != 0);
	}

	fake_close_fin(int plugin_index) {
		track_index = plugin_index;
		hackName = HACK_NAME;
		hack_frequency = 5;
		prescription_probability = 98;
	}
};

extern "C"  HackPacket* CreateHackObject(int plugin_tracking_index) {
	return new fake_close_fin(plugin_tracking_index);
}

extern "C" void DeleteHackObject(HackPacket *who) {
	delete who;
}
