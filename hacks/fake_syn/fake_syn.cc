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
 * a SYN packet, in a sniffer reassembly routine should mean the allocation/
 * opening of a new flow. if this syn packet collide with a previously 
 * allocated tuple, what happen ?
 * 
 * SOURCE: deduction
 * VERIFIED IN:
 * KNOW BUGS:
 * WRITTEN IN VERSION: 0.4.0
 */

#include "Packet.h"

class fake_syn : public HackPacket
{
#define HACK_NAME	"Fake SYN"
public:
	virtual Packet *createHack(Packet &orig_packet)
	{
		orig_packet.selflog(HACK_NAME, "Original packet");
		Packet* ret = new Packet(orig_packet);

		ret->resizePayload(0);
	  
		ret->ip->id = htons(ntohs(ret->ip->id) + (random() % 10));

		ret->tcp->psh = 0;
		ret->tcp->syn = 1;

		ret->tcp->seq = htonl(ntohl(ret->tcp->seq) + 65535 + (random() % 5000));

		/* 20% is a SYN ACK */
		if ((random() % 5) == 0) { 
			ret->tcp->ack = 1;
			ret->tcp->ack_seq = random();
		} else {
			ret->tcp->ack = ret->tcp->ack_seq = 0;
		}

		/* 20% had source and dest port reversed */
		if ((random() % 5) == 0) {
			unsigned short swap = ret->tcp->source;
			ret->tcp->source = ret->tcp->dest;
			ret->tcp->dest = swap;
		}

		ret->position = ANTICIPATION;
		ret->wtf = RANDOMDAMAGE;
		
		ret->selflog(HACK_NAME, "Hacked packet");

		return ret;
	}

	virtual bool Condition(const Packet &orig_packet)
	{
		return (orig_packet.payload != NULL);
	}

	fake_syn(int plugin_index) {
		track_index = plugin_index;
		hackName = HACK_NAME;
		hack_frequency = UNCOMMON;
		prescription_probability = 98;
	}

};

extern "C"  HackPacket* CreateHackObject(int plugin_tracking_index) {
	return new fake_syn(plugin_tracking_index);
}

extern "C" void DeleteHackObject(HackPacket *who) {
	delete who;
}
