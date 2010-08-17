#include "SjUtils.h"
#include "NetIO.h"

#include <cerrno>
#include <cstdlib>
#include <cstdio>
#include <cstring>
#include <unistd.h>
#include <fcntl.h>
#include <net/if.h>
#include <sys/ioctl.h>
#include <linux/if_tun.h>

#include <sys/poll.h>

NetIO::NetIO(SjConf *sjconf)
	: conntrack(sjconf)
{
	struct ifreq orig_gw;
	struct ifreq ifr;
	struct ifreq netifr;
	int ret;
	int tmpfd;
	char tmpsyscmd[MEDIUMBUF];

	runcopy = sjconf->running;

	networkdown_condition = false;
	
	if (getuid() || geteuid()) {
		networkdown_condition = true;
		return;
	}

	/* pseudo sanity check of received data, sjconf had already make something */
	if (strlen(runcopy->gw_ip_addr) < 7 || strlen(runcopy->gw_ip_addr) > 17) {
		internal_log(NULL, ALL_LEVEL, "invalid ip address [%s] is not an IPv4, check the config", runcopy->gw_ip_addr);
		check_call_ret("ip address", EINVAL, -1, false);
		networkdown_condition = true;
		return;
	}

	if (strlen(runcopy->gw_mac_str) != 17) {
		internal_log(NULL, ALL_LEVEL, "invalid mac address [%s] is not a MAC addr, check the config", runcopy->gw_mac_str);
		check_call_ret("mac address", EINVAL, -1, false);
		networkdown_condition = true;
		return;
	}

	if ((tunfd = open("/dev/net/tun", O_RDWR)) == -1) {
		/* this is a serious problem, sniffjoke treat them as FATAL error */
		internal_log(NULL, ALL_LEVEL, "unable to open /dev/net/tun: %s, check the kernel module", strerror(errno));
		check_call_ret("Open /dev/net/tun", errno, tunfd, true);
		return;
	} else {
		internal_log(NULL, DEBUG_LEVEL, "NetIO constructor: /dev/net/tun opened successfull");
	}

	memset(&ifr, 0x00, sizeof(ifr));
	memset(&netifr, 0x00, sizeof(netifr));

	ifr.ifr_flags = IFF_NO_PI;
	ifr.ifr_flags |= IFF_TUN;

	if ((ret = ioctl (tunfd, TUNSETIFF, (void *) &ifr)) == -1) {
		internal_log(NULL, ALL_LEVEL, "Unable to set flags in tunnel interface: %s", strerror(errno));
		check_call_ret("setting TUN flags in /dev/net/tun", errno, ret, true);
	} else {
		internal_log(NULL, DEBUG_LEVEL, "NetIO constructor: setting TUN flags correctly");
	}

	tmpfd = socket (AF_INET, SOCK_DGRAM, 0);
	memcpy(netifr.ifr_name, ifr.ifr_name, IFNAMSIZ);
	netifr.ifr_qlen = 100;
	if ((ret = ioctl (tmpfd, SIOCSIFTXQLEN, (void *) &netifr)) == -1) {
		internal_log(NULL, ALL_LEVEL, "Unable to set SIOCSIFTXQLEN in interface %s: %s", ifr.ifr_name, strerror(errno));
		check_call_ret("Set TUN TXQLEN", errno, ret, true);
	} else {
		internal_log(NULL, DEBUG_LEVEL, "NetIO constructor: setting SIOCSIFTXQLEN correctly in %s", ifr.ifr_name);
	}
	close (tmpfd);
		
	if ((ret = fcntl (tunfd, F_SETFL, O_NONBLOCK)) == -1) {
		internal_log(NULL, ALL_LEVEL, "unable to set non blocking socket: how is this possibile !? %s", strerror(errno));
		check_call_ret("Set TUN NONBLOCK", errno, ret, true);
	} else {
		internal_log(NULL, DEBUG_LEVEL, "NetIO constructor: set NONBLOCK in socket successful");
	}

	if ((ret = fcntl (tunfd, F_SETFD, FD_CLOEXEC)) == -1) {
		internal_log(NULL, ALL_LEVEL, "unable to fcntl FD_CLOEXEC in tunnel: %s", strerror(errno));
		check_call_ret("Set TUN CLOEXEC", errno, ret, false);
	} else {
		internal_log(NULL, DEBUG_LEVEL, "NetIO constructor: set CLOSE on EXIT flag in TUN successful");
	}

	internal_log(NULL, VERBOSE_LEVEL, "deleting default gateway in routing table...");
	system("/sbin/route del default");

	snprintf(tmpsyscmd, MEDIUMBUF, 
		"/sbin/ifconfig tun%d %s pointopoint 1.198.10.5 mtu 1500", 
		runcopy->tun_number,
		runcopy->local_ip_addr
	);
	internal_log(NULL, VERBOSE_LEVEL, "setting up tun%d with the %s's IP (%s) command [%s]\n",
		runcopy->tun_number, runcopy->interface,
		runcopy->local_ip_addr, tmpsyscmd
	);
	system(tmpsyscmd);

	internal_log(NULL, VERBOSE_LEVEL, "setting default gateway our fake TUN endpoint ip address: 1.198.10.5");
	system("/sbin/route add default gw 1.198.10.5");

	strcpy(orig_gw.ifr_name, (const char *)runcopy->interface);
	tmpfd = socket(AF_INET, SOCK_DGRAM, IPPROTO_IP);
		if ((ret = ioctl(tmpfd, SIOCGIFINDEX, &orig_gw)) == -1) 
	{
		internal_log(NULL, ALL_LEVEL, 
			"fatal error, unable to SIOCGIFINDEX %s interface, fix your routing table by hand", 
			runcopy->interface
		);
		check_call_ret("unable to SIOCGIFINDEX network interface", errno, ret, true);
	}
	close(tmpfd);

	if ((netfd = socket(PF_PACKET, SOCK_DGRAM, htons(ETH_P_IP))) == -1) {
		internal_log(NULL, ALL_LEVEL, "unable to open datalink layer packet: %s - fix your routing table by hand",
			strerror(errno)
		);
		check_call_ret("socket for IP packet", errno, netfd, true);
	} else {
		internal_log(NULL, DEBUG_LEVEL, "open successful datalink layer socket packet");
	}

	send_ll.sll_family = PF_PACKET;
	send_ll.sll_protocol = htons(ETH_P_IP);
	send_ll.sll_ifindex = orig_gw.ifr_ifindex;
	send_ll.sll_pkttype = PACKET_HOST;
	send_ll.sll_halen = ETH_ALEN;

	memcpy(send_ll.sll_addr, runcopy->gw_mac_addr, ETH_ALEN);

	if ((ret = bind(netfd, (struct sockaddr *)&send_ll, sizeof(send_ll))) == -1) {
		internal_log(NULL, ALL_LEVEL, "unable to bind datalink layer interface: %s - fix your routing table by hand",
			strerror(errno)
		);
		check_call_ret("bind datalink layer interface", errno, ret, true);
	} else {
		internal_log(NULL, DEBUG_LEVEL, "binding successful datalink layer interface");
	}

	if ((ret = fcntl (netfd, F_SETFL, O_NONBLOCK)) == -1) {
		internal_log(NULL, ALL_LEVEL, "unable to set socket in non blocking mode: %s - fix your routing table by hand",
			strerror(errno)
		);
		check_call_ret("Setting non block in external socket", errno, ret, true);
	} else {
		internal_log(NULL, DEBUG_LEVEL, "setting network socket to non blocking mode successfull");
	}

	fds[0].fd = netfd;
	fds[0].events = POLLIN;
	fds[1].fd = tunfd;
	fds[1].events = POLLIN;
}

NetIO::~NetIO() 
{
	char tmpsyscmd[MEDIUMBUF];

	close(netfd);
	memset(&send_ll, 0x00, sizeof(send_ll));
	
	if (getuid() || geteuid())
		return;

	internal_log(NULL, VERBOSE_LEVEL, "NetIO: deleting our default gw [route del default]");
	system("route del default");

	snprintf(tmpsyscmd, MEDIUMBUF, "ifconfig tun%d down", runcopy->tun_number);
	internal_log(NULL, VERBOSE_LEVEL, "NetIO: shutting down tun%d interface [%s]", runcopy->tun_number, tmpsyscmd);
	system(tmpsyscmd);
	close(tunfd);

	snprintf(tmpsyscmd, MEDIUMBUF, "route add default gw %s", runcopy->gw_ip_addr);
	internal_log(NULL, VERBOSE_LEVEL, "NetIO: restoring previous default gateway [%s]", tmpsyscmd);
	system(tmpsyscmd);
}

void NetIO::network_io()
{
	int burst = BURSTSIZE;
	int nfds;

	while (burst--)
	{
		/* poll wants milliseconds, I want 0.050 sec of delay */
		nfds = poll(fds, 2, 50);

		if (nfds == -1) {
			internal_log(NULL, ALL_LEVEL, "Strange and dangerous error in poll: %s", strerror(errno));
			check_call_ret("error in poll", errno, nfds, true);
		}

		if (!nfds)
			break;

		if (fds[0].revents & POLLIN) {
			if ((size = recv(netfd, pktbuf, MTU, 0)) == -1) {
				if ((errno != EAGAIN) && (errno != EWOULDBLOCK))
				{
					internal_log(NULL, DEBUG_LEVEL, "network_io/recv from network: error: %s", strerror(errno));
					check_call_ret("Reading from network", errno, size, false);
					break;
				}
			} else {
				internal_log(NULL, DEBUG_LEVEL, "network_io/recv from network correctly: %d bytes [sniffjoke %s]", 
							 size, runcopy->sj_run == true ? "running" : "stopped");

				/* add packet in connection tracking queue */
				conntrack.writepacket(NETWORK, pktbuf, size);
			}
		}

		if (fds[1].revents & POLLIN) {
			if ((size = read(tunfd, pktbuf, MTU)) == -1) {
				if ((errno != EAGAIN) && (errno != EWOULDBLOCK)) {
					internal_log(NULL, DEBUG_LEVEL, "network_io/read from tunnel: error: %s", strerror(errno));
					check_call_ret("Reading from tunnel", errno, size, false);
					break;
				}
			} else {
				internal_log(NULL, DEBUG_LEVEL, "network_io/read from tunnel correctly: %d bytes [sniffjoke %s]", 
						size, runcopy->sj_run == true ? "running" : "stopped");

				/* add packet in connection tracking queue */
				conntrack.writepacket(TUNNEL, pktbuf, size);
			}
		}
	}

	if(runcopy->sj_run == true) {
		/* when sniffjoke is running the packet are analyzed and mangled */
		conntrack.analyze_packets_queue();
	} else { /* running->sj_run == false */
		/* all packets must be marked as SEND */
		conntrack.force_send();
	}
}

/* this method send all the packets sets as "SEND" */
void NetIO::queue_flush()
{
	/* 
	 * the NETWORK are flushed on the tunnel.
	 * the other source_t could be LOCAL or TUNNEL;
	 * in both case the packets goes through the network.
	 */
	while ((pkt = conntrack.readpacket()) != NULL) {
		if (pkt->source == NETWORK) {
			if ((size = write(tunfd, pkt->pbuf, pkt->pbuf_size)) == -1) {
				internal_log(NULL, DEBUG_LEVEL, "network_io/write in tunnel error: %s", strerror(errno));
				networkdown_condition = true;
				check_call_ret("Writing in tunnel", errno, size, false);
			} else {
				internal_log(NULL, DEBUG_LEVEL, "network_io/write in tunnel %d successfull [sniffjoke %s]", 
							size, runcopy->sj_run == true ? "running" : "stopped");
			}
		} else {
			if ((size = sendto(netfd, pkt->pbuf, 
				ntohs(pkt->ip->tot_len), 0x00, (struct sockaddr *)&send_ll, sizeof(send_ll))) == -1) 
			{
				internal_log(NULL, DEBUG_LEVEL, "network_io/write in network error: %s", strerror(errno));
				networkdown_condition = true;
				check_call_ret("Writing in network", errno, size, false);
			} else {
				internal_log(NULL, DEBUG_LEVEL, "network_io/write in network %d successfull [sniffjoke %s]",
							 size, runcopy->sj_run == true ? "running" : "stopped");
			}
			
		}
		delete pkt;
	}
}

bool NetIO::is_network_down() {
	return networkdown_condition;
}
