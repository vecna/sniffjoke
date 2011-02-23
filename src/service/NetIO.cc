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

#include <fcntl.h>
#include <poll.h>
#include <linux/if_tun.h>
#include <net/if.h>
#include <sys/ioctl.h>

NetIO::NetIO(sj_config& runcfg) :
runconfig(runcfg)
{
    LOG_DEBUG("");

    struct ifreq ifr;
    struct ifreq netifr;
    struct ifreq orig_gw;
    int ret;
    int tmp_flags;
    int tmpfd;
    char cmd[MEDIUMBUF];

    if (getuid() || geteuid())
        RUNTIME_EXCEPTION("required root privileges");

    memset(&send_ll, 0x00, sizeof (send_ll));
    memset(&ifr, 0x00, sizeof (ifr));
    memset(&netifr, 0x00, sizeof (netifr));
    memset(&orig_gw, 0x00, sizeof (orig_gw));

    /* pseudo sanity check of received data, sjconf had already make something */
    if (strlen(runconfig.gw_ip_addr) < 7 || strlen(runconfig.gw_ip_addr) > 17)
    {
        RUNTIME_EXCEPTION("invalid ip address [%s] is not an IPv4, check the config",
                          runconfig.gw_ip_addr);
    }

    if (strlen(runconfig.gw_mac_str) != 17)
    {
        RUNTIME_EXCEPTION("invalid mac address [%s] is not a MAC addr, check the config",
                          runconfig.gw_mac_str);
    }

    if ((tunfd = open("/dev/net/tun", O_RDWR)) != -1)
        LOG_DEBUG("/dev/net/tun opened successfully");
    else
    {
        RUNTIME_EXCEPTION("unable to open /dev/net/tun: %s, check the kernel module",
                          strerror(errno));
    }

    /* IFF_TUN is for IP. */
    /* IFF_NO_PI is for not receiving extra meta packet information. */
    ifr.ifr_flags = IFF_TUN | IFF_NO_PI;

    if ((ret = ioctl(tunfd, TUNSETIFF, (void *) &ifr)) != -1)
        LOG_DEBUG("flags set successfully in tun socket");
    else
    {
        RUNTIME_EXCEPTION("unable to set flags in tunnel socket: %s",
                          strerror(errno));
    }

    tmpfd = socket(AF_INET, SOCK_DGRAM, 0);
    memcpy(netifr.ifr_name, ifr.ifr_name, IFNAMSIZ);
    netifr.ifr_qlen = 4096;
    if ((ret = ioctl(tmpfd, SIOCSIFTXQLEN, (void *) &netifr)) != -1)
        LOG_DEBUG("ioctl(SIOCGIFINDEX) executed successfully on interface %s", ifr.ifr_name);
    else
    {
        RUNTIME_EXCEPTION("unable to execute ioctl(SIOCGIFINDEX) on interface %s: %s",
                          ifr.ifr_name, strerror(errno));
    }

    close(tmpfd);

    if (((tmp_flags = fcntl(tunfd, F_GETFD)) != -1) && (fcntl(tunfd, F_SETFD, tmp_flags | FD_CLOEXEC) != -1))
        LOG_DEBUG("flag FD_CLOEXEC set successfully in tun socket");
    else
    {
        RUNTIME_EXCEPTION("unable to set flag FD_CLOEXEC in tun socket: %s",
                          strerror(errno));
    }

    LOG_VERBOSE("deleting default gateway in routing table");
    pclose(popen("route del default", "r"));

    snprintf(cmd, sizeof (cmd), "ifconfig tun%d %s pointopoint 1.198.10.5 mtu %d",
             runconfig.tun_number, runconfig.local_ip_addr, MTU_FAKE);
    LOG_VERBOSE("setting up tun % d with the % s's IP (%s) command [%s]",
                runconfig.tun_number, runconfig.interface, runconfig.local_ip_addr, cmd);
    pclose(popen(cmd, "r"));

    LOG_VERBOSE("setting default gateway our fake TUN endpoint ip address: 1.198.10.5");
    pclose(popen("route add default gw 1.198.10.5", "r"));

    strncpy(orig_gw.ifr_name, (const char *) runconfig.interface, sizeof (orig_gw.ifr_name));
    tmpfd = socket(AF_INET, SOCK_DGRAM, IPPROTO_IP);

    if ((ret = ioctl(tmpfd, SIOCGIFINDEX, &orig_gw)) != -1)
        LOG_DEBUG("ioctl(SIOCGIFINDEX) executed successfully on interface %s", runconfig.interface);
    else
    {
        RUNTIME_EXCEPTION("unable to execute ioctl(SIOCGIFINDEX) on interface %s: %s",
                          runconfig.interface, strerror(errno));
    }

    close(tmpfd);

    if ((netfd = socket(PF_PACKET, SOCK_DGRAM, htons(ETH_P_IP))) != -1)
        LOG_DEBUG("datalink layer socket packet opened successfully");
    else
    {
        RUNTIME_EXCEPTION("unable to open datalink layer packet: %s",
                          strerror(errno));
    }

    send_ll.sll_family = PF_PACKET;
    send_ll.sll_protocol = htons(ETH_P_IP);
    send_ll.sll_ifindex = orig_gw.ifr_ifindex;
    send_ll.sll_hatype = 0;
    send_ll.sll_pkttype = PACKET_HOST;
    send_ll.sll_halen = ETH_ALEN;

    memset(&send_ll.sll_addr, 0xFF, sizeof (send_ll.sll_addr));
    memcpy(send_ll.sll_addr, runconfig.gw_mac_addr, ETH_ALEN);

    if ((ret = bind(netfd, (struct sockaddr *) &send_ll, sizeof (send_ll))) != -1)
        LOG_DEBUG("binding datalink layer interface successfully");
    else
        RUNTIME_EXCEPTION("unable to bind datalink layer interface: %s", strerror(errno));

    snprintf(cmd, sizeof (cmd), "iptables -A INPUT -m mac --mac-source %s -j DROP", runconfig.gw_mac_str);
    LOG_ALL("dropping all traffic from the gateway [%s]", cmd);
    pclose(popen(cmd, "r"));

    fds[0].fd = tunfd;
    fds[1].fd = netfd;
}

NetIO::~NetIO(void)
{
    LOG_DEBUG("");

    char cmd[MEDIUMBUF];

    if (getuid() || geteuid())
        LOG_VERBOSE("not root: unable to restore default gw");
    else
    {
        LOG_VERBOSE("deleting our default gw [route del default]");
        pclose(popen("route del default", "r"));

        snprintf(cmd, sizeof (cmd), "ifconfig tun%d down", runconfig.tun_number);
        LOG_VERBOSE("shutting down tun%d interface [%s]", runconfig.tun_number, cmd);
        pclose(popen(cmd, "r"));

        snprintf(cmd, sizeof (cmd), "route add default gw %s", runconfig.gw_ip_addr);
        LOG_VERBOSE("restoring previous default gateway [%s]", cmd);
        pclose(popen(cmd, "r"));

        snprintf(cmd, sizeof (cmd), "iptables -D INPUT -m mac --mac-source %s -j DROP", runconfig.gw_mac_str);
        LOG_VERBOSE("deleting the filtering rule: [%s]", cmd);
        pclose(popen(cmd, "r"));
    }

    close(tunfd);
    close(netfd);
}

void NetIO::prepareConntrack(TCPTrack *ct)
{
    conntrack = ct;
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
             * if there are not data to flush out the poll
             * timeout is set to 1ms
             */

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

        if (fds[0].revents & POLLIN)
        {
            /* it's possibile to read from tunfd */
            ret = read(tunfd, pktbuf, MTU_FAKE);

            if (ret == -1)
                RUNTIME_EXCEPTION("error reading from tunnel: %s", strerror(errno));

            conntrack->writepacket(TUNNEL, pktbuf, ret);
        }

        if (fds[0].revents & POLLOUT)
        {
            /* it's possibile to write in tunfd */
            ret = write(tunfd, (void*) &(pkt_net->pbuf[0]), pkt_net->pbuf.size());

            if (ret == -1) /* on single thread applications after a poll a write returns -1 only on error's case. */
                RUNTIME_EXCEPTION("error writing in tunnel: %s", strerror(errno));

            /* corretly written in tunfd */
            delete pkt_net;
            pkt_net = conntrack->readpacket(NETWORK);
        }

        /* This section of code is not used actively because manage the
         * traffic sent FROM THE GATEWAY TO THE TUNNEL.
         * the kernel is received the data without sniffjoke mangling, because
         * the default gateway is sending the packete to the eth/wifi mac address
         *
         * but this code is require to make the ICMP & SYNACK analyzed 
         * and the TTL to be discerned. a wise usage of local firewall will
         * drop all the incoming packet or a different usage of che packet queue
         * inside conntrack. we are dealing with this.
         */
        if (fds[1].revents & POLLIN)
        {
            /* it's possible to read from netfd */
            ret = recv(netfd, pktbuf, MTU, 0);

            if (ret == -1)
                RUNTIME_EXCEPTION("error reading from network: %s", strerror(errno));

            conntrack->writepacket(NETWORK, pktbuf, ret);
        }

        if (fds[1].revents & POLLOUT)
        {
            /* it's possibile to write in netfd */
            ret = sendto(netfd, (void*) &(pkt_tun->pbuf[0]), pkt_tun->pbuf.size(), 0x00, (struct sockaddr *) &send_ll, sizeof (send_ll));

            if (ret == -1) /* on single thread applications after a poll a write returns -1 only on error's case. */
                RUNTIME_EXCEPTION("error writing in network: %s", strerror(errno));

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
    conntrack->analyzePacketQueue();
}
