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
	runcopy(runcfg)
{
	debug.log(VERBOSE_LEVEL, __func__);

	struct ifreq orig_gw;
	struct ifreq ifr;
	struct ifreq netifr;
	int ret;
	int tmpfd;
	char cmd[MEDIUMBUF];

	if (getuid() || geteuid())
		SJ_RUNTIME_EXCEPTION();

	/* pseudo sanity check of received data, sjconf had already make something */
	if (strlen(runcopy.gw_ip_addr) < 7 || strlen(runcopy.gw_ip_addr) > 17) {
		debug.log(ALL_LEVEL, "NetIO: invalid ip address [%s] is not an IPv4, check the config", runcopy.gw_ip_addr);
		SJ_RUNTIME_EXCEPTION();
	}

	if (strlen(runcopy.gw_mac_str) != 17) {
		debug.log(ALL_LEVEL, "NetIO: invalid mac address [%s] is not a MAC addr, check the config", runcopy.gw_mac_str);
		SJ_RUNTIME_EXCEPTION();
	}

	if ((tunfd = open("/dev/net/tun", O_RDWR)) == -1) {
		/* this is a serious problem, sniffjoke treat them as FATAL error */
		debug.log(ALL_LEVEL, "NetIO: unable to open /dev/net/tun: %s, check the kernel module", strerror(errno));
		SJ_RUNTIME_EXCEPTION();
	} else {
		debug.log(DEBUG_LEVEL, "NetIO: /dev/net/tun opened successfull");
	}

	memset(&ifr, 0x00, sizeof(ifr));
	memset(&netifr, 0x00, sizeof(netifr));

	ifr.ifr_flags = IFF_NO_PI;
	ifr.ifr_flags |= IFF_TUN;

	if ((ret = ioctl (tunfd, TUNSETIFF, (void *) &ifr)) == -1) {
		debug.log(ALL_LEVEL, "NetIO: unable to set flags in tunnel interface: %s", strerror(errno));
		SJ_RUNTIME_EXCEPTION();
	} else {
		debug.log(DEBUG_LEVEL, "NetIO: setting TUN flags correctly");
	}

	tmpfd = socket (AF_INET, SOCK_DGRAM, 0);
	memcpy(netifr.ifr_name, ifr.ifr_name, IFNAMSIZ);
	netifr.ifr_qlen = 100;
	if ((ret = ioctl (tmpfd, SIOCSIFTXQLEN, (void *) &netifr)) == -1) {
		debug.log(ALL_LEVEL, "NetIO: unable to set SIOCSIFTXQLEN in interface %s: %s", ifr.ifr_name, strerror(errno));
		SJ_RUNTIME_EXCEPTION();
	} else {
		debug.log(DEBUG_LEVEL, "NetIO: setting SIOCSIFTXQLEN correctly in %s", ifr.ifr_name);
	}
	close (tmpfd);
		
	if ((ret = fcntl (tunfd, F_SETFL, O_NONBLOCK)) == -1) {
		debug.log(ALL_LEVEL, "NetIO: unable to set non blocking socket: how is this possibile !? %s", strerror(errno));
		SJ_RUNTIME_EXCEPTION();
	} else {
		debug.log(DEBUG_LEVEL, "NetIO: set NONBLOCK in socket successful");
	}

	if ((ret = fcntl (tunfd, F_SETFD, FD_CLOEXEC)) == -1) {
		debug.log(ALL_LEVEL, "NetIO: unable to fcntl FD_CLOEXEC in tunnel: %s", strerror(errno));
		SJ_RUNTIME_EXCEPTION();
	} else {
		debug.log(DEBUG_LEVEL, "NetIO: set CLOSE on EXIT flag in TUN successful");
	}

	debug.log(VERBOSE_LEVEL, "NetIO: deleting default gateway in routing table...");
	system("/sbin/route del default");

	snprintf(cmd, MEDIUMBUF, 
		"/sbin/ifconfig tun%d %s pointopoint 1.198.10.5 mtu %d", 
		runcopy.tun_number,
		runcopy.local_ip_addr,
		MTU_FAKE
	);
	debug.log(VERBOSE_LEVEL, "NetIO: setting up tun%d with the %s's IP (%s) command [%s]",
		runcopy.tun_number, runcopy.interface, runcopy.local_ip_addr, cmd
	);
	pclose(popen(cmd, "r"));

	debug.log(VERBOSE_LEVEL, "NetIO: setting default gateway our fake TUN endpoint ip address: 1.198.10.5");
	system("/sbin/route add default gw 1.198.10.5");

	strcpy(orig_gw.ifr_name, (const char *)runcopy.interface);
	tmpfd = socket(AF_INET, SOCK_DGRAM, IPPROTO_IP);
	
	if ((ret = ioctl(tmpfd, SIOCGIFINDEX, &orig_gw)) == -1) 
	{
		debug.log(ALL_LEVEL, "NetIO: fatal error, unable to SIOCGIFINDEX %s interface, fix your routing table by hand",
			runcopy.interface);
		SJ_RUNTIME_EXCEPTION();
	}

	close(tmpfd);

	if ((netfd = socket(PF_PACKET, SOCK_DGRAM, htons(ETH_P_IP))) == -1) {
		debug.log(ALL_LEVEL, "NetIO: unable to open datalink layer packet: %s - fix your routing table by hand",
			strerror(errno)
		);
		SJ_RUNTIME_EXCEPTION();
	} else {
		debug.log(DEBUG_LEVEL, "NetIO: open successful datalink layer socket packet");
	}

	send_ll.sll_family = PF_PACKET;
	send_ll.sll_protocol = htons(ETH_P_IP);
	send_ll.sll_ifindex = orig_gw.ifr_ifindex;
	send_ll.sll_hatype = 0;
	send_ll.sll_pkttype = PACKET_HOST;
	send_ll.sll_halen = ETH_ALEN;

	memset(send_ll.sll_addr, 0xFF, sizeof(send_ll.sll_addr));
	memcpy(send_ll.sll_addr, runcopy.gw_mac_addr, ETH_ALEN);

	if ((ret = bind(netfd, (struct sockaddr *)&send_ll, sizeof(send_ll))) == -1) {
		debug.log(ALL_LEVEL, "NetIO: unable to bind datalink layer interface: %s - fix your routing table by hand",
			strerror(errno)
		);
		SJ_RUNTIME_EXCEPTION();
	} else {
		debug.log(DEBUG_LEVEL, "NetIO: binding successful datalink layer interface");
	}

	if ((ret = fcntl (netfd, F_SETFL, O_NONBLOCK)) == -1) {
		debug.log(ALL_LEVEL, "NetIO: unable to set socket in non blocking mode: %s - fix your routing table by hand",
			strerror(errno)
		);
		SJ_RUNTIME_EXCEPTION();
	} else {
		debug.log(DEBUG_LEVEL, "NetIO: setting network socket to non blocking mode successfull");
	}

	fds[0].fd = netfd;
	fds[0].events = POLLIN;
	fds[1].fd = tunfd;
	fds[1].events = POLLIN;
}

NetIO::~NetIO(void) 
{
	debug.log(VERBOSE_LEVEL, __func__);

	char cmd[MEDIUMBUF];

	close(netfd);
	memset(&send_ll, 0x00, sizeof(send_ll));
	
	if (getuid() || geteuid()) {
		debug.log(ALL_LEVEL, "~NetIO: not root: unable to restore default gw");
		return;
	}

	debug.log(VERBOSE_LEVEL, "~NetIO: deleting our default gw [route del default]");
	system("route del default");

	snprintf(cmd, MEDIUMBUF, "ifconfig tun%d down", runcopy.tun_number);
	debug.log(VERBOSE_LEVEL, "~NetIO: shutting down tun%d interface [%s]", runcopy.tun_number, cmd);
	pclose(popen(cmd, "r"));
	close(tunfd);

	snprintf(cmd, MEDIUMBUF, "route add default gw %s", runcopy.gw_ip_addr);
	debug.log(VERBOSE_LEVEL, "~NetIO: restoring previous default gateway [%s]", cmd);
	pclose(popen(cmd, "r"));
}

void NetIO::prepare_conntrack(TCPTrack *ct)
{
	conntrack = ct;
}

void NetIO::network_io(void)
{
	int nfds;

	/*
	 * Having a burst size of 5 pkt and a poll timeout of 10 ms
	 * we assure to call conntrack->analyze_packets_queue() with a
	 *  max interval of 50 ms.
	 */
	int burst = 5; /* the real value is burst * 2, because in one cycle we can read a pkt from netfd and a pkt from tunfd */
	int timeout_ms = 10;

	while (burst--)
	{
		nfds = poll(fds, 2, timeout_ms);

		if (nfds <= 0) {
			if (nfds == -1) {
	                        debug.log(ALL_LEVEL, "network_io: strange and dangerous error in poll: %s", strerror(errno));
				SJ_RUNTIME_EXCEPTION();
			}
			break;
		}

		if (fds[0].revents) { /* POLLIN is the unique event managed */
			if ((size = recv(netfd, pktbuf, MTU, 0)) == -1) {
				if ((errno != EAGAIN) && (errno != EWOULDBLOCK))
				{
					debug.log(DEBUG_LEVEL, "network_io: recv from network: error: %s", strerror(errno));
					break;
				}
			} else {
				/* add packet in connection tracking queue */
				conntrack->writepacket(NETWORK, pktbuf, size);
			}
		}

		if (fds[1].revents) { /* POLLIN is the unique event managed */
			if ((size = read(tunfd, pktbuf, MTU_FAKE)) == -1) {
				if ((errno != EAGAIN) && (errno != EWOULDBLOCK)) {
					debug.log(DEBUG_LEVEL, "network_io: read from tunnel: error: %s", strerror(errno));
					break;
				}
			} else {
				/* add packet in connection tracking queue */
				conntrack->writepacket(TUNNEL, pktbuf, size);
			}
		}
	}

	if(runcopy.active == true) {
		/* when sniffjoke is active the packet are analyzed and mangled */
		conntrack->analyze_packets_queue();
	} else { /* running->sj_run == false */
		/* all packets must be marked as SEND */
		conntrack->force_send();
	}
}

/* this method send all the packets sets as "SEND" */
void NetIO::queue_flush(void)
{
	/* 
	 * the NETWORK are flushed on the tunnel.
	 * the other source_t could be LOCAL or TUNNEL;
	 * in both case the packets goes through the network.
	 */
	while ((pkt = conntrack->readpacket()) != NULL) {
		if (pkt->source == NETWORK) {
			if ((size = write(tunfd, (void*)&(pkt->pbuf[0]), pkt->pbuf.size())) == -1) {
				debug.log(DEBUG_LEVEL, "queue_flush: write in tunnel error: %s", strerror(errno));
				SJ_RUNTIME_EXCEPTION();
			} else {
				debug.log(DEBUG_LEVEL, "queue_flush: write in tunnel %d successfull [sniffjoke %s]", 
					size, runcopy.active == true ? "active" : "stopped");
			}
		} else {
			if ((size = sendto(netfd, (void*)&(pkt->pbuf[0]), 
				ntohs(pkt->ip->tot_len), 0x00, (struct sockaddr *)&send_ll, sizeof(send_ll))) == -1) 
			{
				debug.log(DEBUG_LEVEL, "queue_flush: write in network error: %s", strerror(errno));
				SJ_RUNTIME_EXCEPTION();
			} else {
				debug.log(DEBUG_LEVEL, "queue_flush: write in network %d successfull [sniffjoke %s]",
					size, runcopy.active == true ? "active" : "stopped");
			}
		}
		delete pkt;
	}
}
