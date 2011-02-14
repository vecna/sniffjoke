/*
 *   SniffJoke is a software able to confuse the Internet traffic analysis,
 *   developed with the aim to improve digital privacy in communications and
 *   to show and test some securiy weakness in traffic analysis software.
 *   
 *   Copyright (C) 2011 vecna <vecna@delirandom.net>
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
 * This hack scatter one single packet of large payload in a lot of little
 * chunck, is the first base for developing: 1) overlapped chunk 
 * 2) chained hacks
 * 
 * SOURCE: deduction, 
 * VERIFIED IN:
 * KNOW BUGS:
 * WRITTEN IN VERSION: 0.4.0
 */

#include "service/Hack.h"

#define MIN_SCRAMBLE_PACKET 100
#define MIN_BLOCK_SPLIT     50
#define OVERLAPPED_SIZE     40
#define SCATTER_PKT_LOG     "scatterPacket.plugin.log"

class scatter_packet : public Hack
{
private:
    pluginLogHandler *pLH;

#define HACK_NAME "Scatter Packet"
public:
	virtual void createHack(const Packet &origpkt, uint8_t availableScramble)
	{
		uint8_t pkts, i;
        uint32_t seqbefore = (ntohl(origpkt.tcp->seq) - origpkt.datalen);
        uint32_t newsizes = (MIN_BLOCK_SPLIT + OVERLAPPED_SIZE);
        uint32_t currently_send = 0;

        pkts = (origpkt.datalen / MIN_BLOCK_SPLIT) + 1;

	    for(i = 0; i < pkts; i++)
        {
			Packet* const pkt = new Packet(origpkt);
            uint32_t thisdatalen = ((origpkt.datalen - currently_send) % MIN_BLOCK_SPLIT);

            pkt->tcppayloadResize(newsizes);
            memset(pkt->payload, 'A', newsizes);

            memcpy(pkt->payload, &origpkt.payload[i * MIN_BLOCK_SPLIT], thisdatalen);
            currently_send += thisdatalen;
            pkt->tcp->seq = htonl(seqbefore + currently_send);

			pkt->ip->id = htons(ntohs(pkt->ip->id) - 10 + (random() % 20));

			pkt->position = POSTICIPATION;
			pkt->wtf = INNOCENT;
			pktVector.push_back(pkt);
		}

        removeOrigPkt = true;
	}

    /* the only acceptable Scramble is INNOCENT, because the hack is based on
     * overlap the fragment of the same packet */
	virtual bool Condition(const Packet &origpkt, uint8_t availableScramble)
	{
		if (origpkt.payload != NULL && origpkt.datalen > MIN_SCRAMBLE_PACKET)
        {
            return true;
        }

        return false;
	}

	virtual bool initializeHack(uint8_t configuredScramble)
	{
        pLH = new pluginLogHandler( const_cast<const char *>(HACK_NAME), const_cast<const char *>(SCATTER_PKT_LOG));

        if ( ISSET_INNOCENT(configuredScramble) && !ISSET_INNOCENT(~configuredScramble) ) {
            LOG_ALL("%s hack supports only INNOCENT scramble type", HACK_NAME);
        }
		return true;
	}

	scatter_packet(bool forcedTest) : Hack(HACK_NAME, forcedTest ? AGG_ALWAYS : AGG_RARE ) {};
};

extern "C"  Hack* CreateHackObject(bool forcedTest)
{
	return new scatter_packet(forcedTest);
}

extern "C" void DeleteHackObject(Hack *who)
{
	delete who;
}

extern "C" const char *versionValue()
{
 	return SW_VERSION;
}
