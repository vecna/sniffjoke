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

#include "Hack.h"

class fake_seq : public Hack
{
#define HACK_NAME	"Fake SEQ"
public:
	virtual void createHack(const Packet &orig_packet)
	{
		orig_packet.selflog(HACK_NAME, "Original packet");

		Packet* pkt = new Packet(orig_packet);

		int diff = ntohs(pkt->ip->tot_len) - ((pkt->ip->ihl * 4) + (pkt->tcp->doff * 4));
		
		if(diff > 200) {
			diff = random() % 200;
			pkt->TCPPAYLOAD_resize(diff);
		}	
		
		int what = (random() % 3);

		pkt->ip->id = htons(ntohs(pkt->ip->id) + (random() % 10));

		if (what == 0)
			what = 2;

		if (what == 1) 
			pkt->tcp->seq = htonl(ntohl(pkt->tcp->seq) - (random() % 5000));

		if (what == 2)
			pkt->tcp->seq = htonl(ntohl(pkt->tcp->seq) + (random() % 5000));
				
		pkt->tcp->window = htons((random() % 80) * 64);
		pkt->tcp->ack = pkt->tcp->ack_seq = 0;

		pkt->TCPPAYLOAD_fillrandom();

		pkt->position = ANY_POSITION;
		pkt->wtf = RANDOMDAMAGE;

		pkt->selflog(HACK_NAME, "Hacked packet");

		pktVector.push_back(pkt);
	}

	virtual bool Condition(const Packet &orig_packet)
	{
		return (
			!orig_packet.tcp->syn &&
			!orig_packet.tcp->rst &&
			!orig_packet.tcp->fin &&
			orig_packet.payload != NULL
		);
	}

	fake_seq() {
		hackName = HACK_NAME;
		hackFrequency = TIMEBASED5S;
	}

};

extern "C"  Hack* CreateHackObject() {
	return new fake_seq();
}

extern "C" void DeleteHackObject(Hack *who) {
	delete who;
}

extern "C" const char *versionValue() {
 	return SW_VERSION;
}
