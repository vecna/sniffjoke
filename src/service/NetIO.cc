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

#include "NetIO.h"
#include "UserConf.h"

#include <event.h>
#include <pcap.h>

extern auto_ptr<UserConf> userconf;

static void netio_recv_cb(struct bufferevent *sabe, void *arg)
{
    struct iodesc * const desc = (struct iodesc *) arg;

    uint16_t pktsize;

    if (desc->pktrecv.size() == 0)
    {
        if (bufferevent_read(desc->buff_ev, &pktsize, sizeof (pktsize)) != sizeof (pktsize))
            goto netio_recv_error;

        desc->pktrecv.resize(ntohs(pktsize));
        bufferevent_setwatermark(desc->buff_ev, EV_READ, desc->pktrecv.size(), desc->pktrecv.size());
    }
    else
    {
        if (bufferevent_read(desc->buff_ev, &desc->pktrecv[0], desc->pktrecv.size()) != desc->pktrecv.size())
            goto netio_recv_error;

        desc->netio->conntrack->writepacket(desc->source, &desc->pktrecv[0], desc->pktrecv.size());

        desc->pktrecv.clear();
        bufferevent_setwatermark(desc->buff_ev, EV_READ, sizeof (pktsize), sizeof (pktsize));
    }

    return;

netio_recv_error:
    LOG_ALL("error reading from janus %smitm socket", (desc->source == NETWORK) ? "net" : "tun");
    event_loopbreak();
}

static void netio_error_cb(struct bufferevent *sabe, short what, void *arg)
{
    struct iodesc * const desc = (struct iodesc *) arg;
    LOG_ALL("error over janus %smitm socket", (desc->source == NETWORK) ? "net" : "tun");
    event_loopbreak();
}

int NetIO::JanusConnect(uint16_t port)
{
    struct sockaddr_in addr;

    int sock = socket(PF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (sock == -1)
    {
        RUNTIME_EXCEPTION("unable to allocate resources for janus socket [%s:%u]",
                          userconf->runcfg.janus_address, port);
    }

    memset(&addr, 0, sizeof (addr));
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = inet_addr(userconf->runcfg.janus_address);
    addr.sin_port = htons(port);

    if (connect(sock, (struct sockaddr *) &addr, sizeof (addr)) == -1)
    {
        RUNTIME_EXCEPTION("unable to connect to janus socket [%s:%u]",
                          userconf->runcfg.janus_address, port);
    }

    LOG_ALL("correctly coonected to Janus at address %s on port %u", userconf->runcfg.janus_address, port);

    return sock;
}

void NetIO::setupNET()
{
    netfd = JanusConnect(userconf->runcfg.janus_portin);
}

void NetIO::setupTUN()
{
    tunfd = JanusConnect(userconf->runcfg.janus_portout);
}

void NetIO::dumpPacket(Packet &pkt)
{
    vector<unsigned char> dumppkt(4 + pkt.pbuf.size(), 0);
    *(uint32_t *)&dumppkt[0] = PF_INET;
    memcpy(&dumppkt[4], &pkt.pbuf[0], pkt.pbuf.size());
    struct pcap_pkthdr pph;
    memset(&pph, 0, sizeof (pph));
    gettimeofday(&pph.ts, NULL);
    pph.caplen = 4 + pkt.pbuf.size();
    pph.len = 4 + pkt.pbuf.size();
    pcap_dump((unsigned char*)dumper, &pph, &dumppkt[0]);
}

void NetIO::write(void)
{
    for (uint8_t i = 0; i < 2; ++i)
    {
        Packet *sendpkt;
        while ((sendpkt = conntrack->readpacket(netiodesc[i].source)) != NULL)
        {
            uint16_t size = htons(sendpkt->pbuf.size());
            bufferevent_write(netiodesc[i].buff_ev, &size, sizeof (size));
            bufferevent_write(netiodesc[i].buff_ev, &(sendpkt->pbuf[0]), sendpkt->pbuf.size());

            if(dumper != NULL)
                dumpPacket(*sendpkt);

            delete sendpkt;
        }
    }
}

NetIO::NetIO(TCPTrack *ct, bool dump_packets) :
conntrack(ct)
{
    LOG_DEBUG("");

    setupNET();
    setupTUN();

    netiodesc[0].netio = this;
    netiodesc[0].source = NETWORK;
    netiodesc[0].buff_ev = bufferevent_new(netfd, netio_recv_cb, NULL, netio_error_cb, &netiodesc[0]);
    bufferevent_setwatermark(netiodesc[0].buff_ev, EV_READ, 2, 2);
    bufferevent_enable(netiodesc[0].buff_ev, EV_READ);

    netiodesc[1].netio = this;
    netiodesc[1].source = TUNNEL;
    netiodesc[1].buff_ev = bufferevent_new(tunfd, netio_recv_cb, NULL, netio_error_cb, &netiodesc[1]);
    bufferevent_setwatermark(netiodesc[1].buff_ev, EV_READ, 2, 2);
    bufferevent_enable(netiodesc[1].buff_ev, EV_READ);

    if(dump_packets)
    {
        LOG_ALL("dumping traffic to %s", FILE_PACKETSDUMP);

        dumper = pcap_dump_open(pcap_open_dead(0, 1500), FILE_PACKETSDUMP);

        if(dumper == NULL)
        {
            RUNTIME_EXCEPTION("unable to open packets dump file [%s]",
                              strerror(errno));
        }
    }
    else
    {
        dumper = NULL;
    }

}

NetIO::~NetIO(void)
{
    LOG_DEBUG("");

    close(netfd);
    close(tunfd);

    LOG_ALL("correctly disconnected from Janus");

    for (uint8_t i = 0; i < 2; ++i)
        bufferevent_free(netiodesc[i].buff_ev);

    if(dumper != NULL)
        pcap_dump_close(dumper);
}
