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

#include <fcntl.h>
#include <poll.h>
#include <linux/if_tun.h>
#include <net/if.h>
#include <sys/ioctl.h>

extern auto_ptr<UserConf> userconf;

void NetIO::setupNET()
{
    int tmpflags;
    int tmpfd;
    struct ifreq tmpifr;

    memset(&tmpifr, 0x00, sizeof (tmpifr));

    if ((netfd = socket(PF_PACKET, SOCK_DGRAM, htons(ETH_P_IP))) != -1)
        LOG_DEBUG("datalink layer socket packet opened successfully");
    else
        RUNTIME_EXCEPTION("unable to open datalink layer packet: %s", strerror(errno));

    if (((tmpflags = fcntl(netfd, F_GETFD)) != -1) && (fcntl(netfd, F_SETFD, tmpflags | FD_CLOEXEC) != -1))
        LOG_DEBUG("flag FD_CLOEXEC set successfully in netfd (F_SETFD)");
    else
        RUNTIME_EXCEPTION("unable to set flag FD_CLOEXEC on netfd (F_SETFD): %s", strerror(errno));

    strncpy(tmpifr.ifr_name, userconf->runcfg.net_iface_name, sizeof (tmpifr.ifr_name));
    if (ioctl(netfd, SIOCGIFINDEX, &tmpifr) != -1)
        LOG_DEBUG("ioctl(SIOCGIFINDEX) executed successfully on interface %s", userconf->runcfg.net_iface_name);
    else
        RUNTIME_EXCEPTION("unable to execute ioctl(SIOCGIFINDEX) on interface %s: %s", userconf->runcfg.net_iface_name, strerror(errno));

    memset(&send_ll, 0x00, sizeof (send_ll));
    send_ll.sll_family = PF_PACKET;
    send_ll.sll_protocol = htons(ETH_P_IP);
    send_ll.sll_ifindex = tmpifr.ifr_ifindex;
    send_ll.sll_hatype = 0;
    send_ll.sll_pkttype = PACKET_HOST;
    send_ll.sll_halen = ETH_ALEN;
    memcpy(send_ll.sll_addr, userconf->runcfg.gw_mac_addr, ETH_ALEN);

    if (bind(netfd, (struct sockaddr *) &send_ll, sizeof (send_ll)) != -1)
        LOG_DEBUG("binding datalink layer interface successfully");
    else
        RUNTIME_EXCEPTION("unable to bind datalink layer interface: %s", strerror(errno));

    tmpfd = socket(AF_INET, SOCK_DGRAM, IPPROTO_IP);

    if (ioctl(tmpfd, SIOCGIFMTU, &tmpifr) != -1)
        LOG_DEBUG("netfd mtu correctly get read %u (SIOCGIFMTU)", tmpifr.ifr_mtu);
    else
        RUNTIME_EXCEPTION("unable to get netfd mtu(SIOCGIFMTU): %s", strerror(errno));
    userconf->runcfg.net_iface_mtu = tmpifr.ifr_mtu;

    close(tmpfd);
}

void NetIO::setupTUN()
{
    const char *tundev = "/dev/net/tun";

    int tmpflags;
    int tmpfd;
    struct ifreq tmpifr;

    memset(&tmpifr, 0x00, sizeof (tmpifr));

    if ((tunfd = open(tundev, O_RDWR)) != -1)
        LOG_DEBUG("%s opened successfully", tundev);
    else
        RUNTIME_EXCEPTION("unable to open %s: %s, check the kernel module", tundev, strerror(errno));

    if (((tmpflags = fcntl(tunfd, F_GETFD)) != -1) && (fcntl(tunfd, F_SETFD, tmpflags | FD_CLOEXEC) != -1))
        LOG_DEBUG("flag FD_CLOEXEC set successfully on tunfd (F_SETFD)");
    else
        RUNTIME_EXCEPTION("unable to set flag FD_CLOEXEC on tunfd (F_SETFD): %s", strerror(errno));

    strncpy(tmpifr.ifr_name, TUN_IF_NAME, sizeof (tmpifr.ifr_name));
    tmpifr.ifr_flags = IFF_TUN | IFF_NO_PI;
    if (ioctl(tunfd, TUNSETIFF, &tmpifr) != -1)
        LOG_DEBUG("flags set successfully on tunfd (TUNSETIFF)");
    else
        RUNTIME_EXCEPTION("unable to set flags on tunfd (TUNSETIFF): %s", strerror(errno));

    tmpfd = socket(AF_INET, SOCK_DGRAM, IPPROTO_IP);

    if (ioctl(tmpfd, SIOCGIFFLAGS, &tmpifr) != -1)
        LOG_DEBUG("tunfd flags correctly read (SIOCGIFFLAGS)");
    else
        RUNTIME_EXCEPTION("unable to get tunfd flags (SIOCGIFFLAGS): %s", strerror(errno));
    tmpifr.ifr_flags |= IFF_UP | IFF_RUNNING | IFF_POINTOPOINT;

    if (ioctl(tmpfd, SIOCSIFFLAGS, &tmpifr) != -1)
        LOG_DEBUG("tunfd flags correctly set (SIOCSIFFLAGS)");
    else
        RUNTIME_EXCEPTION("unable to get tunfd flags (SIOCSIFFLAGS): %s", strerror(errno));

    userconf->runcfg.tun_iface_mtu = userconf->runcfg.net_iface_mtu - TUN_IF_MTU_DIFF;
    tmpifr.ifr_mtu = userconf->runcfg.tun_iface_mtu;
    if (ioctl(tmpfd, SIOCSIFMTU, &tmpifr) != -1)
        LOG_DEBUG("tunfd mtu correctly set to %u (SIOCSIFMTU)", userconf->runcfg.tun_iface_mtu);
    else
        RUNTIME_EXCEPTION("unable to set tunfd mtu to %u (SIOCSIFMTU): %s", userconf->runcfg.tun_iface_mtu, strerror(errno));

    ((struct sockaddr_in *) &tmpifr.ifr_addr)->sin_family = AF_INET;
    ((struct sockaddr_in *) &tmpifr.ifr_addr)->sin_addr.s_addr = inet_addr(userconf->runcfg.net_iface_ip);
    if (ioctl(tmpfd, SIOCSIFADDR, &tmpifr) != -1)
        LOG_DEBUG("tunfd local addr correctly set to %s", userconf->runcfg.net_iface_ip);
    else
        RUNTIME_EXCEPTION("unable to set tunfd local addr to %s: %s", userconf->runcfg.net_iface_ip, strerror(errno));

    ((struct sockaddr_in *) &tmpifr.ifr_addr)->sin_family = AF_INET;
    ((struct sockaddr_in *) &tmpifr.ifr_addr)->sin_addr.s_addr = inet_addr(DEFAULT_FAKE_IPADDR);
    memcpy(userconf->runcfg.tun_iface_ip, DEFAULT_FAKE_IPADDR, strlen(DEFAULT_FAKE_IPADDR));
    if (ioctl(tmpfd, SIOCSIFDSTADDR, &tmpifr) != -1)
        LOG_DEBUG("tunfd point-to-point dest addr correctly set to %s", DEFAULT_FAKE_IPADDR);
    else
        RUNTIME_EXCEPTION("unable to set tunfd point-to-point dest addr  to %s: %s", DEFAULT_FAKE_IPADDR, strerror(errno));


    close(tmpfd);
}

NetIO::NetIO(void)
{
    LOG_DEBUG("");

    char cmd[MEDIUMBUF];

    if (getuid() || geteuid())
        RUNTIME_EXCEPTION("required root privileges");

    /* pseudo sanity check of received data, sjconf had already make something */
    if (strlen(userconf->runcfg.gw_ip_addr) < 7 || strlen(userconf->runcfg.gw_ip_addr) > 17)
        RUNTIME_EXCEPTION("invalid ip address [%s] is not an IPv4, check the config", userconf->runcfg.gw_ip_addr);

    if (strlen(userconf->runcfg.gw_mac_str) != 17)
        RUNTIME_EXCEPTION("invalid mac address [%s] is not a MAC, check the config", userconf->runcfg.gw_mac_str);

    setupNET();
    setupTUN();

    fds[0].fd = tunfd;
    fds[1].fd = netfd;

    snprintf(cmd, sizeof (cmd), "route del default");
    LOG_VERBOSE("deleting default gateway in routing table");
    execOSCmd(cmd);

    snprintf(cmd, sizeof (cmd), "route add default gw %s", DEFAULT_FAKE_IPADDR"");
    LOG_VERBOSE("setting default gateway our fake TUN endpoint ip address: %s", DEFAULT_FAKE_IPADDR);
    execOSCmd(cmd);

    snprintf(cmd, sizeof (cmd), "iptables -A INPUT -m mac --mac-source %s -j DROP", userconf->runcfg.gw_mac_str);
    LOG_ALL("dropping all traffic from the gateway [%s]", cmd);
    execOSCmd(cmd);
}

NetIO::~NetIO(void)
{
    LOG_DEBUG("");

    char cmd[MEDIUMBUF];

    if (getuid() || geteuid())
        LOG_VERBOSE("this process (%d) is not root: unable to restore default gw", getpid());
    else
    {
        snprintf(cmd, sizeof (cmd), "route del default");
        LOG_VERBOSE("root process (%d): deleting our default gw [route del default]", getpid());
        execOSCmd(cmd);

        snprintf(cmd, sizeof (cmd), "ifconfig %s down", TUN_IF_NAME);
        LOG_VERBOSE("shutting down  interface [%s]", TUN_IF_NAME, cmd);
        execOSCmd(cmd);

        snprintf(cmd, sizeof (cmd), "route add default gw %s", userconf->runcfg.gw_ip_addr);
        LOG_VERBOSE("restoring previous default gateway [%s]", cmd);
        execOSCmd(cmd);

        snprintf(cmd, sizeof (cmd), "iptables -D INPUT -m mac --mac-source %s -j DROP", userconf->runcfg.gw_mac_str);
        LOG_VERBOSE("deleting the filtering rule: [%s]", cmd);
        execOSCmd(cmd);
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
    uint32_t max_cycle = NETIOBURSTSIZE;

    vector<unsigned char> pktbuf(userconf->runcfg.net_iface_mtu);

    ssize_t ret;

    Packet *pkt_tun = conntrack->readpacket(TUNNEL);
    Packet *pkt_net = conntrack->readpacket(NETWORK);

    while (pkt_tun != NULL || pkt_net != NULL || max_cycle)
    {
        if (max_cycle != 0) max_cycle--;

        if (pkt_tun != NULL || pkt_net != NULL)
        {
            /*
             * if there is some data to flush out the poll
             * timeout is set to infinite
             */

            fds[0].events = (pkt_net != NULL) ? POLLIN | POLLOUT : POLLIN;
            fds[1].events = (pkt_tun != NULL) ? POLLIN | POLLOUT : POLLIN;

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

        if (fds[0].revents & POLLIN) /* it's possibile to read from tunfd */
        {
            ret = read(tunfd, &(pktbuf[0]), userconf->runcfg.tun_iface_mtu);

            if (ret == -1)
                RUNTIME_EXCEPTION("error reading from tunnel: %s", strerror(errno));

            conntrack->writepacket(TUNNEL, &(pktbuf[0]), ret);
        }

        if (fds[0].revents & POLLOUT) /* it's possibile to write in tunfd */
        {
            ret = write(tunfd, &(pkt_net->pbuf[0]), pkt_net->pbuf.size());

            if (ret == -1) /* on single thread applications after a poll a write returns -1 only on error's case. */
                RUNTIME_EXCEPTION("error writing in tunnel: %s", strerror(errno));

            /* correctly written in tunfd */
            delete pkt_net;
            pkt_net = conntrack->readpacket(NETWORK);
        }

        if (fds[1].revents & POLLIN) /* it's possible to read from netfd */
        {
            ret = recv(netfd, &(pktbuf[0]), userconf->runcfg.net_iface_mtu, 0);

            if (ret == -1)
                RUNTIME_EXCEPTION("error reading from network: %s", strerror(errno));

            conntrack->writepacket(NETWORK, &(pktbuf[0]), ret);
        }

        if (fds[1].revents & POLLOUT) /* it's possibile to write in netfd */
        {
            ret = sendto(netfd, &(pkt_tun->pbuf[0]), pkt_tun->pbuf.size(), 0x00, (struct sockaddr *) &send_ll, sizeof (send_ll));

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

