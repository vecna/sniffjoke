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

#include "HackPacket.h"
/*
 * HACK COMMENT:, every hacks require intensive comments because should cause 
 * malfunction, or KILL THE INTERNET :)
 * 
 * SjH__fake_data_anticipation and SjH__fake_data_posticipation
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

class FakeDataAnticipation : public HackPacket
{
private:
public:
	virtual Packet *createHack(Packet &orig_packet)
	{
		Packet ret = Packet(orig_packet);
		ret.fillRandomPayload();

		/* REQUIRED - checked */
		ret.wtf = PRESCRIPTION;
		ret.position = ANTICIPATION;

#if 0
                internal_log(NULL, HACKS_DEBUG,
                        "HACKSDEBUG: %s [court:%d, position:%d] (lo:%d %s:%d #%d) id %u len %d-%d[%d] data %d {%d%d%d%d%d}",
			__FILE__,
                        court_word,
                        injpkt->position,
                        ntohs(injpkt->tcp->source),
                        inet_ntoa(*((struct in_addr *)&injpkt->ip->daddr)),
                        ntohs(injpkt->tcp->dest), session->packet_number,
                        ntohs(injpkt->ip->id),
                        injpkt->orig_pktlen,
                        injpkt->pbuf.size(), ntohs(injpkt->ip->tot_len),
                        ntohs(injpkt->ip->tot_len) - ((injpkt->ip->ihl * 4) + (injpkt->tcp->doff * 4)),
                        injpkt->tcp->syn, injpkt->tcp->ack, injpkt->tcp->psh, injpkt->tcp->fin, injpkt->tcp->rst
                );
#endif
		return <Packet *>(this);
	}

	virtual bool condition(const Packet &orig_packet)
	{
		return (orig_packet.payload != NULL);		
	}

	FakeDataAnticipation(const Packet &dummy) {
		/* REQUIRED - checked */
		hack_frequency = 50;
		/* REQUIRED - checked */
		hackname = "FakeDataAnticipation";
	}

	~FakeDataAnticipation() { }
};

extern "C"  HackPacket * CreateHackObject() {
	return new FakeDataAnticipation;
}

extern "C" DeleteHackPacket * DeleteHackObject(HackPacket *who) {
	delete who;
}
