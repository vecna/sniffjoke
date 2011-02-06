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

#include "NetIO.h"

#include <fcntl.h>
#include <poll.h>
#include <linux/if_tun.h>
#include <net/if.h>
#include <sys/ioctl.h>

NetIO::NetIO(sj_config& runcfg) :
runconfig(runcfg)
{
    debug.log(VERBOSE_LEVEL, __func__);

    struct ifreq orig_gw;
    struct ifreq ifr;
    struct ifreq netifr;
    int ret;
    int tmp_flags;
    int tmpfd;
    char cmd[MEDIUMBUF];

    if (getuid() || geteuid())
        SJ_RUNTIME_EXCEPTION("");

    /* pseudo sanity check of received data, sjconf had already make something */
    if (strlen(runconfig.gw_ip_addr) < 7 || strlen(runconfig.gw_ip_addr) > 17)
    {
        debug.log(ALL_LEVEL, "NetIO: invalid ip address [%s] is not an IPv4, check the config", runconfig.gw_ip_addr);
        SJ_RUNTIME_EXCEPTION("");
    }

    if (strlen(runconfig.gw_mac_str) != 17)
    {
        debug.log(ALL_LEVEL, "NetIO: invalid mac address [%s] is not a MAC addr, check the config", runconfig.gw_mac_str);
        SJ_RUNTIME_EXCEPTION("");
    }

    if ((tunfd = open("/dev/net/tun", O_RDWR)) != -1)
    {
        debug.log(DEBUG_LEVEL, "NetIO: /dev/net/tun opened successfully");
    }
    else
    {
        debug.log(ALL_LEVEL, "NetIO: unable to open /dev/net/tun: %s, check the kernel module", strerror(errno));
        SJ_RUNTIME_EXCEPTION("");
    }

    memset(&ifr, 0x00, sizeof (ifr));
    memset(&netifr, 0x00, sizeof (netifr));

    /* IFF_TUN is for IP. */
    /* IFF_NO_PI is for not receiving extra meta packet information. */
    ifr.ifr_flags = IFF_TUN | IFF_NO_PI;


    if ((ret = ioctl(tunfd, TUNSETIFF, (void *) &ifr)) != -1)
    {
        debug.log(DEBUG_LEVEL, "NetIO: flags set successfully in tun socket");
    }
    else
    {
        debug.log(ALL_LEVEL, "NetIO: unable to set flags in tunnel socket: %s", strerror(errno));
        SJ_RUNTIME_EXCEPTION("");
    }

    tmpfd = socket(AF_INET, SOCK_DGRAM, 0);
    memcpy(netifr.ifr_name, ifr.ifr_name, IFNAMSIZ);
    netifr.ifr_qlen = 4096;
    if ((ret = ioctl(tmpfd, SIOCSIFTXQLEN, (void *) &netifr)) != -1)
    {
        debug.log(DEBUG_LEVEL, "NetIO: ioctl(SIOCGIFINDEX) executed successfully on interface %s", ifr.ifr_name);
    }
    else
    {
        debug.log(ALL_LEVEL, "NetIO: unable to execute ioctl(SIOCGIFINDEX) on interface %s: %s", ifr.ifr_name, strerror(errno));
        SJ_RUNTIME_EXCEPTION("");
    }
    close(tmpfd);


    if (((tmp_flags = fcntl(tunfd, F_GETFD)) != -1) && (fcntl(tunfd, F_SETFD, tmp_flags | FD_CLOEXEC) != -1))
    {
        debug.log(DEBUG_LEVEL, "NetIO: flag FD_CLOEXEC set successfully in tun socket");
    }
    else
    {
        debug.log(ALL_LEVEL, "NetIO: unable to set flag FD_CLOEXEC in tun socket: %s", strerror(errno));
        SJ_RUNTIME_EXCEPTION("");
    }

    debug.log(VERBOSE_LEVEL, "NetIO: deleting default gateway in routing table...");
    system("/sbin/route del default");

    snprintf(cmd, sizeof (cmd),
             "/sbin/ifconfig tun%d %s pointopoint 1.198.10.5 mtu %d",
             runconfig.tun_number,
             runconfig.local_ip_addr,
             MTU_FAKE
             );
    debug.log(VERBOSE_LEVEL, "NetIO: setting up tun%d with the %s's IP (%s) command [%s]",
              runconfig.tun_number, runconfig.interface, runconfig.local_ip_addr, cmd
              );
    pclose(popen(cmd, "r"));

    debug.log(VERBOSE_LEVEL, "NetIO: setting default gateway our fake TUN endpoint ip address: 1.198.10.5");
    system("/sbin/route add default gw 1.198.10.5");

    strcpy(orig_gw.ifr_name, (const char *) runconfig.interface);
    tmpfd = socket(AF_INET, SOCK_DGRAM, IPPROTO_IP);

    if ((ret = ioctl(tmpfd, SIOCGIFINDEX, &orig_gw)) != -1)
    {
        debug.log(DEBUG_LEVEL, "NetIO: ioctl(SIOCGIFINDEX) executed successfully on interface %s", runconfig.interface);
    }
    else
    {
        debug.log(ALL_LEVEL, "NetIO: unable to execute ioctl(SIOCGIFINDEX) on interface %s: %s",
                  runconfig.interface, strerror(errno));
        SJ_RUNTIME_EXCEPTION("");
    }

    close(tmpfd);

    if ((netfd = socket(PF_PACKET, SOCK_DGRAM, htons(ETH_P_IP))) != -1)
    {
        debug.log(DEBUG_LEVEL, "NetIO: datalink layer socket packet opened successfully");
    }
    else
    {
        debug.log(ALL_LEVEL, "NetIO: unable to open datalink layer packet: %s",
                  strerror(errno)
                  );
        SJ_RUNTIME_EXCEPTION("");
    }

    send_ll.sll_family = PF_PACKET;
    send_ll.sll_protocol = htons(ETH_P_IP);
    send_ll.sll_ifindex = orig_gw.ifr_ifindex;
    send_ll.sll_hatype = 0;
    send_ll.sll_pkttype = PACKET_HOST;
    send_ll.sll_halen = ETH_ALEN;

    memset(send_ll.sll_addr, 0xFF, sizeof (send_ll.sll_addr));
    memcpy(send_ll.sll_addr, runconfig.gw_mac_addr, ETH_ALEN);

    if ((ret = bind(netfd, (struct sockaddr *) &send_ll, sizeof (send_ll))) != -1)
    {
        debug.log(DEBUG_LEVEL, "NetIO: binding datalink layer interface successfully");
    }
    else
    {
        debug.log(ALL_LEVEL, "NetIO: unable to bind datalink layer interface: %s",
                  strerror(errno)
                  );
        SJ_RUNTIME_EXCEPTION("");
    }

    fds[0].fd = tunfd;
    fds[1].fd = netfd;
}

NetIO::~NetIO(void)
{
    debug.log(VERBOSE_LEVEL, __func__);

    char cmd[MEDIUMBUF];

    if (getuid() || geteuid())
    {
        debug.log(VERBOSE_LEVEL, "~NetIO: not root: unable to restore default gw");
    }
    else
    {
        debug.log(VERBOSE_LEVEL, "~NetIO: deleting our default gw [route del default]");
        system("route del default");

        snprintf(cmd, sizeof (cmd), "ifconfig tun%d down", runconfig.tun_number);
        debug.log(VERBOSE_LEVEL, "~NetIO: shutting down tun%d interface [%s]", runconfig.tun_number, cmd);
        pclose(popen(cmd, "r"));

        snprintf(cmd, sizeof (cmd), "route add default gw %s", runconfig.gw_ip_addr);
        debug.log(VERBOSE_LEVEL, "~NetIO: restoring previous default gateway [%s]", cmd);
        pclose(popen(cmd, "r"));
    }

    close(tunfd);
    close(netfd);
}

void NetIO::prepare_conntrack(TCPTrack *ct)
{
    conntrack = ct;
}

void NetIO::network_io(void)
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
    uint32_t max_cycle = 10;

    ssize_t ret;

    Packet *pkt_tun = conntrack->readpacket(TUNNEL);
    Packet *pkt_net = conntrack->readpacket(NETWORK);

    while (pkt_tun != NULL || pkt_net != NULL || max_cycle)
    {
        if (max_cycle != 0) max_cycle--;

        if (conntrack->p_queue.size() < TCPTRACK_QUEUE_MAX_LEN)
        {
            fds[0].events = POLLIN;
            fds[1].events = POLLIN;
        }
        else
        {
            fds[0].events = 0;
            fds[1].events = 0;
        }

        if (pkt_tun != NULL || pkt_net != NULL)
        {

            /*
             * if there is some data to flush out the poll
             * timeout is set to infinite
             */

            fds[0].events |= (pkt_net != NULL) ? POLLOUT : 0;
            fds[1].events |= (pkt_tun != NULL) ? POLLOUT : 0;

            nfds = poll(fds, 2, -1);
        }
        else
        {

            /*
             * if there is some data to flush out the poll
             * timeout is set to 1ms
             */

            timespec timeout;
            timeout.tv_sec = 0;
            timeout.tv_nsec = 40000;
            nfds = ppoll(fds, 2, &timeout, NULL);
        }

        if (!nfds)
            continue;

        /* in the three cases poll/ppoll is set, now we check the nfds return value */
        if (nfds == -1)
        {
            debug.log(ALL_LEVEL, "network_io: strange and dangerous error in ppoll: %s", strerror(errno));
            SJ_RUNTIME_EXCEPTION("");
        }

        if (fds[0].revents & POLLIN)
        {
            /* it's possibile to read from tunfd */
            ret = read(tunfd, pktbuf, MTU_FAKE);

            if (ret == -1)
            {
                debug.log(ALL_LEVEL, "%s: read from tunnel: %s", __func__, strerror(errno));
                SJ_RUNTIME_EXCEPTION(strerror(errno));
            }

            if (runconfig.active == true)
            {
                conntrack->writepacket(TUNNEL, pktbuf, ret);
            }
            else
            {
                if (sendto(netfd, pktbuf, ret, 0x00, (struct sockaddr *) &send_ll, sizeof (send_ll)) != ret)
                {
                    debug.log(ALL_LEVEL, "%s: send to network: %s", __func__, strerror(errno));
                    SJ_RUNTIME_EXCEPTION(strerror(errno));
                }
            }
        }

        if (fds[0].revents & POLLOUT)
        {
            /* it's possibile to write in tunfd */
            ret = write(tunfd, (void*) &(pkt_net->pbuf[0]), pkt_net->pbuf.size());

            if (ret == -1)
            {
                /*
                 * on single thread applications after a poll a write returns
                 * -1 only on error's case.
                 */
                debug.log(DEBUG_LEVEL, "network_io: write in tunnel: error: %s", strerror(errno));
                SJ_RUNTIME_EXCEPTION(strerror(errno));
            }

            /* corretly written in tunfd */
            delete pkt_net;
            pkt_net = conntrack->readpacket(NETWORK);
        }

        if (fds[1].revents & POLLIN)
        {
            /* it's possible to read from netfd */
            ret = recv(netfd, pktbuf, MTU, 0);

            if (ret == -1)
            {
                debug.log(ALL_LEVEL, "%s: read from network: %s", __func__, strerror(errno));
                SJ_RUNTIME_EXCEPTION(strerror(errno));
            }

            if (runconfig.active == true)
            {
                conntrack->writepacket(NETWORK, pktbuf, ret);
            }
            else
            {
                /* sniffjoke it's disabled? we make a blocking write, because
                 * an intensive traffic will return -1 on a non ready to write socket */
                if (write(tunfd, pktbuf, ret) != ret)
                {
                    debug.log(ALL_LEVEL, "%s: write in tunnel: %s", __func__, strerror(errno));
                    SJ_RUNTIME_EXCEPTION(strerror(errno));
                }
            }
        }

        if (fds[1].revents & POLLOUT)
        {
            /* it's possibile to write in netfd */
            ret = sendto(netfd, (void*) &(pkt_tun->pbuf[0]), pkt_tun->pbuf.size(), 0x00, (struct sockaddr *) &send_ll, sizeof (send_ll));

            if (ret == -1)
            {
                /*
                 * on single thread applications after a poll a write returns
                 * -1 only on error's case.
                 */
                debug.log(DEBUG_LEVEL, "network_io: write in network: error: %s", strerror(errno));
                SJ_RUNTIME_EXCEPTION(strerror(errno));
            }

            /* correctly written in netfd */
            delete pkt_tun;
            pkt_tun = conntrack->readpacket(TUNNEL);
        }
    }

    /*
     * If the flow control arrives here:
     *   - output data has been flushed entirely
     *   - there is some input data to handle (maximum 20 pkts i/o) or
     *     a max delay of 10ms it's passed.
     */
    conntrack->analyze_packets_queue();
}