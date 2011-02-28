/*
 *   SniffJoke is a software able to confuse the Internet traffic analysis,
 *   developed with the aim to improve digital privacy in communications and
 *   to show and test some securiy weakness in traffic analysis software.
 *   
 *   Copyright (C) 2008 vecna <vecna@delirandom.net>
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

#ifndef SJ_TCPTRACK_H
#define SJ_TCPTRACK_H

#include "Utils.h"
#include "UserConf.h"
#include "Packet.h"
#include "PacketQueue.h"
#include "SessionTrack.h"
#include "TTLFocus.h"
#include "HackPool.h"

class TCPTrack
{
private:
    const struct sj_config &runconfig;

    SessionTrackMap &sessiontrack_map;
    TTLFocusMap &ttlfocus_map;
    HackPool &hack_pool;

    uint32_t derivePercentage(uint32_t, uint16_t);
    bool percentage(uint32_t, uint16_t, uint16_t);
    uint8_t discernAvailScramble(Packet &);

    void injectTTLProbe(TTLFocus &);
    bool extractTTLinfo(Packet &);
    void execTTLBruteforces();

    bool notifyIncoming(Packet &);
    bool injectHack(Packet &);
    bool lastPktFix(Packet &);

    void handleYoungPackets();
    void handleKeepPackets();
    void handleHackPackets();

public:

    PacketQueue p_queue;

    TCPTrack(const sj_config &, HackPool &, SessionTrackMap &, TTLFocusMap &);
    ~TCPTrack(void);

    void writepacket(source_t, const unsigned char *, int);
    Packet* readpacket(source_t);
    void analyzePacketQueue();
};

#endif /* SJ_TCPTRACK_H */
