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
 * SOURCE: phrack, deduction
 * VERIFIED IN:
 * KNOW BUGS:
 */

#include "service/Hack.h"

class fake_close_fin : public Hack
{
#define HACK_NAME "Fake FIN"

public:

    virtual void createHack(const Packet &origpkt, uint8_t availableScramble)
    {
        Packet * const pkt = new Packet(origpkt);

        pkt->ip->id = htons(ntohs(pkt->ip->id) - 10 + (random() % 20));

        pkt->tcp->seq = htonl(ntohl(pkt->tcp->seq) - pkt->datalen + 1);

        pkt->tcp->psh = 0;
        pkt->tcp->fin = 1;

        pkt->tcppayloadResize(0);

        pkt->position = ANTICIPATION;
        pkt->wtf = pktRandomDamage(availableScramble & supportedScramble);
        pkt->choosableScramble = (availableScramble & supportedScramble);
        pkt->proto = TCP;

        pktVector.push_back(pkt);
    }

    virtual bool Condition(const Packet &origpkt, uint8_t availableScramble)
    {
        return (!origpkt.tcp->syn &&
                !origpkt.tcp->rst &&
                !origpkt.tcp->fin);
    }

    virtual bool initializeHack(uint8_t configuredScramble)
    {
        supportedScramble = configuredScramble;
        return true;
    }

    fake_close_fin(bool forcedTest) : Hack(HACK_NAME, forcedTest ? AGG_ALWAYS : AGG_PACKETS30PEEK)
    {
    };
};

extern "C" Hack* CreateHackObject(bool forcedTest)
{
    return new fake_close_fin(forcedTest);
}

extern "C" void DeleteHackObject(Hack *who)
{
    delete who;
}

extern "C" const char *versionValue()
{
    return SW_VERSION;
}
