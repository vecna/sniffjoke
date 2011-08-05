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

#ifndef SJ_NETIO_H
#define SJ_NETIO_H

#include "Utils.h"
#include "TCPTrack.h"

#include <pcap.h>

class NetIO;

struct iodesc
{
    struct bufferevent *buff_ev;
    source_t source;
    vector<unsigned char> pktrecv;
    NetIO *netio;
};

class NetIO
{
public:

    TCPTrack *conntrack;

    pcap_dumper_t *dumper;

    /* tunfd/netfd: file descriptor for I/O purpose */
    int tunfd;
    int netfd;

    struct iodesc netiodesc[2];

    int JanusConnect(uint16_t);
    void setupTUN();
    void setupNET();
    void dumpPacket(Packet &);

    /*
     * networkdown_condition express if the network is down and sniffjoke must be interrupted
     *       --- but not killed!
     */

    NetIO(TCPTrack *, bool);
    ~NetIO(void);
    void write(void);
};

#endif /* SJ_NETIO_H */
