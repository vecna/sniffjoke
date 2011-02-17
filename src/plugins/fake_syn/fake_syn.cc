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

#include "service/Hack.h"

class fake_syn : public Hack
{
#define HACK_NAME "Fake SYN"

public:

    virtual void createHack(const Packet &origpkt, uint8_t availableScramble)
    {
        uint8_t pkts = 2;
        while (pkts--)
        {
            Packet * const pkt = new Packet(origpkt);

            pkt->ip->id = htons(ntohs(pkt->ip->id) - 10 + (random() % 20));

            pkt->tcp->psh = 0;
            pkt->tcp->syn = 1;

            pkt->tcp->seq = htonl(ntohl(pkt->tcp->seq) + 65535 + (random() % 5000));

            /* 20% is a SYN ACK */
            if ((random() % 5) == 0)
            {
                pkt->tcp->ack = 1;
                pkt->tcp->ack_seq = random();
            }
            else
            {
                pkt->tcp->ack = pkt->tcp->ack_seq = 0;
            }

            /* 20% had source and dest port reversed */
            if ((random() % 5) == 0)
            {
                uint16_t swap = pkt->tcp->source;
                pkt->tcp->source = pkt->tcp->dest;
                pkt->tcp->dest = swap;
            }

            pkt->tcppayloadResize(0);

            if (pkts == 2) /* first packet */
                pkt->position = ANTICIPATION;
            else /* second packet */
                pkt->position = POSTICIPATION;

            pkt->wtf = pktRandomDamage(availableScramble & supportedScramble);
            pkt->choosableScramble = (availableScramble & supportedScramble);

            pktVector.push_back(pkt);
        }
    }

    virtual bool Condition(const Packet &origpkt, uint8_t availableScramble)
    {
        return (origpkt.tcp->syn &&
                !origpkt.tcp->rst &&
                !origpkt.tcp->fin);
    }

    virtual bool initializeHack(uint8_t configuredScramble)
    {
        supportedScramble = configuredScramble;
        return true;
    }

    fake_syn(bool forcedTest) : Hack(HACK_NAME, forcedTest ? AGG_ALWAYS : AGG_RARE)
    {
    };
};

extern "C" Hack* CreateHackObject(bool forcedTest)
{
    return new fake_syn(forcedTest);
}

extern "C" void DeleteHackObject(Hack *who)
{
    delete who;
}

extern "C" const char *versionValue()
{
    return SW_VERSION;
}
