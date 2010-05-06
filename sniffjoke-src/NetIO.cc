#include <iostream>
#include <cerrno>
using namespace std;
#include <stdlib.h>
#include <string.h>
#include <fcntl.h>
#include <netdb.h>
#include <net/if.h>
#include <sys/ioctl.h>
#include <linux/if_tun.h>
#include <linux/if_ether.h>

#include "sniffjoke.h"

NetIO::NetIO(SjConf *sjconf) 
{
	struct ifreq orig_gw;
	struct ifreq ifr;
	struct ifreq netifr;
	int ret;
	int tmpfd;
	char tmpsyscmd[MEDIUMBUF];

	runcopy = sjconf->running;

	error_msg = NULL;
	error_len = 0;

	/* pseudo sanity check of received data, sjconf had already make something */
	if(strlen(runcopy->gw_ip_addr) < 7 || strlen(runcopy->gw_ip_addr) > 17) {
		check_call_ret("ip address", EINVAL, -1, &error_msg, &error_len);
		return ;
	}

	if(strlen(runcopy->gw_mac_str) != 17) {
		check_call_ret("mac address", EINVAL, -1, &error_msg, &error_len);
		return ;
	}

	tunfd = open("/dev/net/tun", O_RDWR);
	if(check_call_ret("Open /dev/net/tun", errno, tunfd, &error_msg, &error_len))
		return ;

	memset(&ifr, 0x00, sizeof(ifr));
	memset(&netifr, 0x00, sizeof(netifr));

	ifr.ifr_flags = IFF_NO_PI;
	ifr.ifr_flags |= IFF_TUN;

	ret = ioctl (tunfd, TUNSETIFF, (void *) &ifr);
	if(check_call_ret("Set TUN flags in /dev/net/tun", errno, ret, &error_msg, &error_len))
		return ;

	tmpfd = socket (AF_INET, SOCK_DGRAM, 0);
	memcpy(netifr.ifr_name, ifr.ifr_name, IFNAMSIZ);
	netifr.ifr_qlen = 100;
	ret = ioctl (tmpfd, SIOCSIFTXQLEN, (void *) &netifr);
	if(check_call_ret("Set TUN TXQLEN", errno, ret, &error_msg, &error_len))
		return ;
	close (tmpfd);
		
	ret = fcntl (tunfd, F_SETFL, O_NONBLOCK);
	if(check_call_ret("Set TUN NONBLOCK", errno, ret))
		return ;
	ret = fcntl (tunfd, F_SETFD, FD_CLOEXEC);
	if(check_call_ret("Set TUN CLOEXEC", errno, ret, &error_msg, &error_len))
		return ;

	printf("deleting 'default' gateway in routing table\n");
	system("/sbin/route del default");

	snprintf(tmpsyscmd, MEDIUMBUF, 
		"/sbin/ifconfig tun%d %s pointopoint 1.198.10.5 mtu 1500", 
		runcopy->tun_number,
		runcopy->local_ip_addr
	);
	printf("setting up tun%d with the %s's IP (%s) with [%s]\n",
		runcopy->tun_number,
		runcopy->interface,
		runcopy->local_ip_addr,
		tmpsyscmd
	);
	system(tmpsyscmd);

	printf("setting default gateway our fake TUN endpoint (1.198.10.5)\n");
	system("/sbin/route add default gw 1.198.10.5");

	strcpy(orig_gw.ifr_name, (const char *)runcopy->interface);
	tmpfd = socket(AF_INET, SOCK_DGRAM, IPPROTO_IP);
        ret = ioctl(tmpfd, SIOCGIFINDEX, &orig_gw);
	if(check_call_ret("Get TUN index", errno, ret, &error_msg, &error_len))
		return ;
        close(tmpfd);

	netfd = socket(PF_PACKET, SOCK_DGRAM, htons(ETH_P_IP));
	if(check_call_ret("Open socket for IP packet", errno, netfd, &error_msg, &error_len))
		return ;

	send_ll.sll_family = PF_PACKET;
	send_ll.sll_protocol = htons(ETH_P_IP);
	send_ll.sll_ifindex = orig_gw.ifr_ifindex;
	send_ll.sll_pkttype = PACKET_HOST;
	send_ll.sll_halen = ETH_ALEN;

	memcpy(send_ll.sll_addr, runcopy->gw_mac_addr, ETH_ALEN);

	ret = bind(netfd, (struct sockaddr *)&send_ll, sizeof(send_ll) );
	if(check_call_ret("Binding interface", errno, ret, &error_msg, &error_len))
		return ;
	
	ret = fcntl (netfd, F_SETFL, O_NONBLOCK);
	if(check_call_ret("Setting non block in external socket", errno, ret, &error_msg, &error_len))
		return ;
}

NetIO::~NetIO() 
{
	char tmpsyscmd[MEDIUMBUF];

	close(epfd);

	close(netfd);
	memset(&send_ll, 0x00, sizeof(send_ll));

	printf("NetIO: deleting our default gw [route del default]\n");
	system("route del default");

	snprintf(tmpsyscmd, MEDIUMBUF, "ifconfig tun%d down", runcopy->tun_number);
	printf("NetIO: shutting down tun%d interface [%s]\n", runcopy->tun_number, tmpsyscmd);
	system(tmpsyscmd);
	close(tunfd);

	snprintf(tmpsyscmd, MEDIUMBUF, "route add default gw %s", runcopy->gw_ip_addr);
	printf("NetIO: restoring previous default gateway [%s]\n", tmpsyscmd);
	system(tmpsyscmd);
}

void NetIO::network_io(source_t sourcetype, TCPTrack *ct)
{
        /* doens't work with MTU 9k, MTU is defined in sniffjoke.h as 1500 */
        static unsigned char pktbuf[MTU];
        int nbyte = 0;
        int burst = 10;

        while( burst-- ) {
                if(sourcetype == NETWORK) {
                        nbyte = recv(netfd, pktbuf, MTU, 0);
                        if(nbyte < 0) { 
				if(errno != EAGAIN)
					check_call_ret("Reading from network", errno, nbyte);
				else
					break;
			}
                }
                else /* sourcetype == TUNNEL */ {
                        nbyte = read(tunfd, pktbuf, MTU);
                        if(nbyte < 0) {
				if(errno != EAGAIN)
					check_call_ret("Reading from tunnel", errno, nbyte);
                	        else
					break;
			}
                }
                              
                /* add packet in connection tracking queue */
                ct->add_packet_queue(sourcetype, pktbuf, nbyte);
        }
}

/* this method send all the packets sets as "SEND" */
void NetIO::queue_flush( TCPTrack *ct )
{
	int wbyt = 0;
	struct packetblock *packet = NULL;

	/* 
 	 * the NETWORK are flushed on the tunnel.
 	 * the other source_t could be LOCAL or TUNNEL;
 	 * in both case the packets goes through the network.
 	 */
	packet = ct->get_pblock(SEND, ANY_SOURCE, ANY_PROTO, false);
	while( packet != NULL )
	{
		if(packet->source == NETWORK) {
			wbyt = write( tunfd, packet->pbuf, packet->pbuf_size );
			check_call_ret("Writing in tunnel", errno, wbyt);
		} else {
			
			if(packet->source != TTLBFORCE) 
			{
				/* fixing TTL, fixing checksum and IP/TCP options */
				ct->last_pkt_fix(packet);
			}
			
			wbyt = sendto(
				netfd, 
				packet->pbuf, 
				ntohs(packet->ip->tot_len),
				0x00,
				(struct sockaddr *)&send_ll,
				sizeof(send_ll)
			);
			check_call_ret("Writing in network", errno, wbyt);
			
		}
		ct->clear_pblock(packet);
		packet = ct->get_pblock(SEND, ANY_SOURCE, ANY_PROTO, true);
	}

#if 0
	/* remove packet marked as DROP */
	packet = ct->get_pblock(DROP, ANY_SOURCE, ANY_PROTO, false);
	while( (packet != NULL )
	{
		ct->clear_pblock(packet);
		packet = ct->get_pblock(DROP, ANY_SOURCE, ANY_PROTO, true);
	}
#endif
}
