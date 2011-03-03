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
 * A reset must be ignored if the ack value is more than last_ack_seq + window,
 * this is a path due to the denial of service named 
 * "Slipping in the window: TCP Reset attacks", linked below
 * this is another ack working in INNOCENT mode, not with GUILTY/PRESCRIPTION
 *
 * SOURCE: deduction, analysis of the DoS [ http://kerneltrap.org/node/3072 ]
 * VERIFIED IN:
 * KNOW BUGS:
 * WRITTEN IN VERSION: 0.4.0
 *
 */

#include "service/Hack.h"

class valid_rst_fake_seq : public Hack
{
#define HACK_NAME "valid RST / fake SEQ"
public:

    virtual void createHack(const Packet &origpkt, uint8_t availableScramble)
    {
        Packet * const pkt = new Packet(origpkt);

        pkt->tcp->seq = htonl(ntohl(pkt->tcp->seq) + 65535 + (random() % 12345));
        pkt->tcp->window = htons((uint16_t) (-1));
        pkt->tcp->ack_seq = htonl(ntohl(pkt->tcp->seq) + 1);
        pkt->tcp->psh = 0;

        pkt->tcppayloadResize(0);

        pkt->position = ANY_POSITION;
        pkt->wtf = INNOCENT;

        /* useless because INNOCENT is never downgraded in last_pkt_fix */
        pkt->choosableScramble = SCRAMBLE_INNOCENT;

        /* this packet will became dangerous if hacked again...
         * is an INNOCENT RST based on the seq... */
        pkt->chainflag = FINALHACK;

        pktVector.push_back(pkt);
    }

    virtual bool Condition(const Packet &origpkt, uint8_t availableScramble)
    {
        if (origpkt.chainflag != HACKUNASSIGNED)
            return false;

        return (origpkt.fragment == false &&
                origpkt.proto == TCP &&
                !origpkt.tcp->syn &&
                !origpkt.tcp->rst &&
                !origpkt.tcp->fin &&
                origpkt.tcp->ack);
    }

    virtual bool initializeHack(uint8_t configuredScramble)
    {
        if (!(ISSET_INNOCENT(configuredScramble) && !ISSET_INNOCENT(~configuredScramble)))
        {
            LOG_ALL("%s plugin supports only INNOCENT scramble type", HACK_NAME);
            return false;
        }

        supportedScramble = SCRAMBLE_INNOCENT;

        return true;
    }

    valid_rst_fake_seq(bool forcedTest) : Hack(HACK_NAME, forcedTest ? AGG_ALWAYS : AGG_STARTPEEK)
    {
    }
};

extern "C" Hack* CreateHackObject(bool forcedTest)
{
    return new valid_rst_fake_seq(forcedTest);
}

extern "C" void DeleteHackObject(Hack *who)
{
    delete who;
}

extern "C" const char *versionValue()
{
    return SW_VERSION;
}
