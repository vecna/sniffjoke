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

        desc->conntrack->writepacket(desc->destination, &desc->pktrecv[0], desc->pktrecv.size());

        desc->pktrecv.clear();
        bufferevent_setwatermark(desc->buff_ev, EV_READ, sizeof (pktsize), sizeof (pktsize));
    }

    return;

netio_recv_error:
    LOG_ALL("error reading from janus %smitm socket", (desc->destination == TUNNEL) ? "net" : "tun");
    event_loopbreak();
}

static void netio_error_cb(struct bufferevent *sabe, short what, void *arg)
{
    struct iodesc * const desc = (struct iodesc *) arg;
    LOG_ALL("error over janus %smitm socket", (desc->destination == TUNNEL) ? "net" : "tun");
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

void NetIO::write(void)
{
    for (uint8_t i = 0; i < 2; ++i)
    {
        uint8_t j = (i == 0) ? 1 : 0;
        Packet *sendpkt;
        while ((sendpkt = conntrack->readpacket(netiodesc[i].source)) != NULL)
        {
            uint16_t size = htons(sendpkt->pbuf.size());
            bufferevent_write(netiodesc[j].buff_ev, &size, sizeof (size));
            bufferevent_write(netiodesc[j].buff_ev, &(sendpkt->pbuf[0]), sendpkt->pbuf.size());
            delete sendpkt;
        }
    }
}

NetIO::NetIO(TCPTrack *ct) :
conntrack(ct)
{
    LOG_DEBUG("");

    setupNET();
    setupTUN();

    netiodesc[0].conntrack = ct;
    netiodesc[0].source = NETWORK;
    netiodesc[0].destination = TUNNEL;
    netiodesc[0].buff_ev = bufferevent_new(netfd, netio_recv_cb, NULL, netio_error_cb, &netiodesc[0]);
    bufferevent_setwatermark(netiodesc[0].buff_ev, EV_READ, 2, 2);
    bufferevent_enable(netiodesc[0].buff_ev, EV_READ);

    netiodesc[1].conntrack = ct;
    netiodesc[1].source = TUNNEL;
    netiodesc[1].destination = NETWORK;
    netiodesc[1].buff_ev = bufferevent_new(tunfd, netio_recv_cb, NULL, netio_error_cb, &netiodesc[1]);
    bufferevent_setwatermark(netiodesc[1].buff_ev, EV_READ, 2, 2);
    bufferevent_enable(netiodesc[1].buff_ev, EV_READ);
}

NetIO::~NetIO(void)
{
    LOG_DEBUG("");

    close(netfd);
    close(tunfd);

    for (uint8_t i = 0; i < 2; ++i)
        bufferevent_free(netiodesc[i].buff_ev);
}