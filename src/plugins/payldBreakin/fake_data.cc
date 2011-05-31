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
 * this hack injects two packets (that will be invalidated with TTL expiring
 * or bad ip options or bad checksum) of the same length of the original packet,
 * one BEFORE and one AFTER the real packet. this cause that the sniffer, that
 * eventually confirms the readed data when the data was acknowledged, to
 * memorize the first packet or the last only (because they share the same
 * sequence number). the reassembled flow appears overridden by the data here
 * injected. shoulds be the leverage for an applicative injection (like a
 * fake mail instead of the real mail, etc...)
 *
 * the hack varies in relation to the packet trying to achive the maximum effect.
 *
 *  1) if the packet is an ip fragment applies fake_fragment();
 *  2) if the packet is a tcp segment applies fake_segment();
 *  3) if the packet is a udp datagram applies fake_datagram();
 * 
 * SOURCE: deduction, analysis of libnids
 * VERIFIED IN:
 * KNOW BUGS:
 * WRITTEN IN VERSION: 0.4.0
 */

#include "service/Plugin.h"

class fake_data : public Plugin
{
#define PLUGIN_NAME "Fake Data"

private:

    Packet* fake_fragment(const Packet &origpkt)
    {
        Packet * const pkt = new Packet(origpkt);

        return pkt;
    }

    Packet* fake_segment(const Packet &origpkt)
    {
        Packet * const pkt = new Packet(origpkt);

        pkt->tcp->rst = 0;
        pkt->tcp->fin = 0;

        /* before, psh was random 50% to be set or not. now I keep the orig */

        /* urg pointer is not used and is a little off topic handle here */
#if 0
        if (random_percent(50))
        {
            pkt->tcp->urg = 1;
            pkt->tcp->urg_ptr = pkt->tcp->seq << random() % 5;
        }
        else
        {
            pkt->tcp->urg = 0;
        }
#endif

        return pkt;
    }

    Packet* fake_datagram(const Packet &origpkt)
    {
        Packet * const pkt = new Packet(origpkt);

        return pkt;
    }

public:

    fake_data() : Plugin(PLUGIN_NAME, AGG_COMMON)
    {
    };

    virtual bool init(uint8_t configuredScramble, char *pluginOption, struct sjEnviron *sjE)
    {
        supportedScrambles = configuredScramble;
        return true;
    }

    virtual bool condition(const Packet &origpkt, uint8_t availableScrambles)
    {
        if (origpkt.chainflag == FINALHACK)
            return false;

        if (origpkt.fragment)
            return true;

        /* a fake data apply only if a data exists */
        if (origpkt.proto == TCP && origpkt.tcppayloadlen > 0)
            return true;

        if (origpkt.proto == UDP && origpkt.udppayloadlen > 0)
            return true;

        return false;
    }

    virtual void apply(const Packet &origpkt, uint8_t availableScrambles)
    {
        judge_t selectedScramble = pktRandomDamage(availableScrambles, supportedScrambles);

        Packet * (fake_data::*perProtoFunction)(const Packet &) = NULL;

        if (origpkt.fragment == false)
        {
            if (origpkt.proto == TCP && origpkt.tcppayload != NULL)
                perProtoFunction = &fake_data::fake_segment;
            else if (origpkt.proto == UDP && origpkt.udppayload != NULL)
                perProtoFunction = &fake_data::fake_datagram;
        }
        else
        {
            perProtoFunction = &fake_data::fake_fragment;
        }

        if (perProtoFunction == NULL)
            return;

        for (uint8_t pkts = 0; pkts < 2; pkts++)
        {
            Packet* pkt = (this->*perProtoFunction)(origpkt);

            pkt->randomizeID();

            pkt->source = PLUGIN;

            if (pkts == 0) /* first packet */
                pkt->position = ANTICIPATION;
            else /* second packet */
                pkt->position = POSTICIPATION;

            pkt->wtf = selectedScramble;
            pkt->choosableScramble = (availableScrambles & supportedScrambles);
            pkt->tcppayloadRandomFill();

            upgradeChainFlag(pkt);

            pktVector.push_back(pkt);
        }
    }
};

extern "C" Plugin* createPluginObj()
{
    return new fake_data();
}

extern "C" void deletePluginObj(Plugin *who)
{
    delete who;
}

extern "C" const char *versionValue()
{
    return SW_VERSION;
}
