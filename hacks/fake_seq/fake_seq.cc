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
 * when a sniffer collect the file using the sequence as stream offset, injecting a
 * completely random seq should cause extremely large and empty flow, truncation or
 * apparently large missinsg block of data.
 * 
 * SOURCE: phrack, analysis of tcpflow, analysis of wireshark
 * VERIFIED IN:
 * KNOW BUGS:
 * WRITTEN IN VERSION: 0.4.0
 */

#include "Packet.h"

class fake_seq : public HackPacket
{
#define HACK_NAME	"Fake SEQ"
public:
	virtual Packet *createHack(Packet &orig_packet)
	{
		orig_packet.selflog(HACK_NAME, "Original packet");
		Packet* ret = new Packet(orig_packet);

		int diff = ntohs(ret->ip->tot_len) - ((ret->ip->ihl * 4) + (ret->tcp->doff * 4));
		
		if(diff > 200) {
			diff = random() % 200;
			ret->resizePayload(diff);
		}	
		
		int what = (random() % 3);

		ret->ip->id = htons(ntohs(ret->ip->id) + (random() % 10));

		if (what == 0)
			what = 2;

		if (what == 1) 
			ret->tcp->seq = htonl(ntohl(ret->tcp->seq) - (random() % 5000));

		if (what == 2)
			ret->tcp->seq = htonl(ntohl(ret->tcp->seq) + (random() % 5000));
				
		ret->tcp->window = htons((random() % 80) * 64);
		ret->tcp->ack = ret->tcp->ack_seq = 0;

		ret->fillRandomPayload();

		ret->position = ANY_POSITION;
		ret->selflog(HACK_NAME, "Hacked packet");

		return ret;
	}

	virtual bool Condition(const Packet &orig_packet)
	{
		return (orig_packet.payload != NULL);
	}

	fake_seq(int plugin_index) {
		track_index = plugin_index;
		hackName = HACK_NAME;
		hack_frequency = 15;
		prescription_probability = 98;
	}

};

extern "C"  HackPacket* CreateHackObject(int plugin_tracking_index) {
	return new fake_seq(plugin_tracking_index);
}

extern "C" void DeleteHackObject(HackPacket *who) {
	delete who;
}
