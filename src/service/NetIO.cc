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

#include <poll.h>

extern auto_ptr<UserConf> userconf;

void NetIO::setupNET()
{
    struct sockaddr_in addr;

    netfd = socket(PF_INET, SOCK_STREAM, IPPROTO_TCP);
    if(netfd == -1)
        RUNTIME_EXCEPTION("unable to allocate resources for janus netmitm socket");

    memset(&addr, 0, sizeof(addr));            
    addr.sin_family      = AF_INET; 
    addr.sin_addr.s_addr = inet_addr("127.0.0.1");   
    addr.sin_port        = htons(10203);  

    if(connect(netfd, (struct sockaddr *) &addr, sizeof(addr)) == -1)
        RUNTIME_EXCEPTION("unable to connect to janus netmitm socket");
}

void NetIO::setupTUN()
{
    struct sockaddr_in addr;

    tunfd = socket(PF_INET, SOCK_STREAM, IPPROTO_TCP);
    if(tunfd == -1)
        RUNTIME_EXCEPTION("unable to allocate resources for janus tunmitm socket");

    memset(&addr, 0, sizeof(addr));
    addr.sin_family      = AF_INET;
    addr.sin_addr.s_addr = inet_addr("127.0.0.1");
    addr.sin_port        = htons(30201);

    if(connect(tunfd, (struct sockaddr *) &addr, sizeof(addr)) == -1)
        RUNTIME_EXCEPTION("unable to connect to janus tunmitm socket");
}

NetIO::NetIO(TCPTrack *ct) :
conntrack(ct)
{
    LOG_DEBUG("");

    setupNET();
    setupTUN();

    fds[0].fd = netfd;
    fds[1].fd = tunfd;
}

NetIO::~NetIO(void)
{
    LOG_DEBUG("");

    close(netfd);
    close(tunfd);
}

void NetIO::networkIO(void)
{
    /*
     * This is a critical function for sniffjoke operativity.
     *
     * this function implements a variable poll step

     * if there is some data to send out the poll timout is set to
     * infinite because it's important to force data flush.
     *
     * if there is no data to send out the poll timeout is always
     * set to 1 ms;
     *
     * with a max cycle count of 10 and a poll timeout of 1ms
     * we will exit if:
     *    - a burst of 20 pkts (10 network + 10 tunnel) has been received;
     *    - a delay of 10ms has passed.
     *
     * read, read, read and than re-read all comments hundred times
     * before thinking to change this :P
     *
     */
    uint32_t max_cycle = NETIOBURSTSIZE;

    vector<unsigned char> recv_buf(MTU);

    uint16_t pkt_size;
    ssize_t ret;
    uint8_t i;

    Packet *send_buf[2];
    send_buf[0] = conntrack->readpacket(NETWORK);
    send_buf[1] = conntrack->readpacket(TUNNEL);

    source_t source;

    while (send_buf[0] != NULL || send_buf[1] != NULL || max_cycle)
    {
        if (max_cycle != 0) max_cycle--;

        if (send_buf[0] != NULL || send_buf[1] != NULL)
        {
            /*
             * if there is some data to flush out the poll
             * timeout is set to infinite
             */

            fds[0].events = (send_buf[0] != NULL) ? POLLIN | POLLOUT : POLLIN;
            fds[1].events = (send_buf[1] != NULL) ? POLLIN | POLLOUT : POLLIN;

            nfds = poll(fds, 2, -1);
        }
        else
        {
            /*
             * if there are not data to flush out the poll
             * timeout is set to 1ms
             */

            fds[0].events = POLLIN;
            fds[1].events = POLLIN;

            timespec timeout;
            timeout.tv_sec = 0;
            timeout.tv_nsec = 1000000;
            nfds = ppoll(fds, 2, &timeout, NULL);
        }

        if (!nfds)
            continue;

        /* in the three cases poll/ppoll is set, now we check the nfds return value */
        if (nfds == -1)
            RUNTIME_EXCEPTION("strange and dangerous error in ppoll: %s", strerror(errno));

        for(i = 0; i < 2; ++i)
        {
            source = (i == 0) ? NETWORK : TUNNEL;

            if (fds[i].revents & POLLIN) /* it's possibile to read from tunfd */
            {
                ret = recv(fds[i].fd, &pkt_size, sizeof(pkt_size), MSG_WAITALL);
                if(ret != sizeof(pkt_size))
                    goto netio_recv_error;
                
                pkt_size = ntohs(pkt_size);

                ret = recv(fds[i].fd, &(recv_buf[0]), pkt_size, MSG_WAITALL);
                if(ret != pkt_size)
                    goto netio_recv_error;

                conntrack->writepacket(source, &(recv_buf[0]), pkt_size);
            }

            if (fds[i].revents & POLLOUT) /* it's possibile to write in tunfd */
            {
                pkt_size = htons(send_buf[i]->pbuf.size());
                ret = send(fds[i].fd, &pkt_size, sizeof(pkt_size), 0);
                if (ret != sizeof(pkt_size))
                    goto netio_send_error;

                ret = send(fds[i].fd, &(send_buf[i]->pbuf[0]), send_buf[i]->pbuf.size(), 0);
                if (ret != (int)send_buf[i]->pbuf.size())
                    goto netio_send_error;

                /* correctly written in tunfd */
                delete send_buf[i];
                send_buf[i] = conntrack->readpacket(source);
            }
        }
    }

    /*
     * If the flow control arrives here:
     *   - output data has been flushed entirely
     *   - there is some input data to handle (maximum 20 pkts i/o) or
     *     a max delay of 10ms it's passed.
     */
    conntrack->analyzePacketQueue();

    return;

netio_recv_error:
    RUNTIME_EXCEPTION("error reading from janus %smitm socket", (source == NETWORK) ? "net" : "tun");

netio_send_error:
    RUNTIME_EXCEPTION("error writing to janus %smitm socket", (source == NETWORK) ? "net" : "tun");
}

