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
 * Some sniffer don't keep attention to the sequence and the data, but to
 * the acknowledge sequence number. a shift sequence hack work sending a fake
 * ACK-packet with a seq_ack totally wrong. this was one of the hacks I've tried
 * to use without GUILTY/PRESCRIPTION invalidation, but as INNOCENT, because 
 * if the ack is shifted more than the window value, the remote host must
 * invalidate them
 *
 * SOURCE: deduction, 
 * VERIFIED IN:
 * KNOW BUGS:
 * WRITTEN IN VERSION: 0.4.0
 */

#include "service/Plugin.h"

class shift_ack : public Plugin
{
#define PLUGIN_NAME "unexpected ACK shift"

public:

    shift_ack() :
    Plugin(PLUGIN_NAME, AGG_RARE)
    {
    }

    virtual bool init(uint8_t configuredScramble, char *pluginOption, struct sjEnviron *sjE)
    {
        supportedScrambles = configuredScramble;
        return true;
    }

    virtual bool condition(const Packet &origpkt, uint8_t availableScrambles)
    {
        if (origpkt.chainflag == FINALHACK)
            return false;

        return (origpkt.fragment == false &&
                origpkt.proto == TCP &&
                !origpkt.tcp->syn &&
                !origpkt.tcp->rst &&
                !origpkt.tcp->fin &&
                origpkt.tcp->ack);
    }

    virtual void apply(const Packet &origpkt, uint8_t availableScrambles)
    {
        Packet * const pkt = new Packet(origpkt);

        pkt->randomizeID();

        pkt->tcp->ack_seq = htonl(ntohl(pkt->tcp->ack_seq) - pkt->maxMTU() + random() % 2 * pkt->maxMTU());

        pkt->source = PLUGIN;
        pkt->position = ANY_POSITION;
        pkt->wtf = pktRandomDamage(availableScrambles, supportedScrambles);
        pkt->choosableScramble = (availableScrambles & supportedScrambles);
        pkt->payloadRandomFill();

        upgradeChainFlag(pkt);

        pktVector.push_back(pkt);
    }
};

extern "C" Plugin* createPluginObj()
{
    return new shift_ack();
}

extern "C" void deletePluginObj(Plugin *who)
{
    delete who;
}

extern "C" const char *versionValue()
{
    return SW_VERSION;
}
