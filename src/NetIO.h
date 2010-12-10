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

#ifndef SJ_NETIO_H
#define SJ_NETIO_H

#include "Utils.h"
#include "UserConf.h"
#include "TCPTrack.h"

#include <poll.h>
#include <netpacket/packet.h>

#define BURSTSIZE       10

class NetIO {
private:
	/* 
	 * these data are required for handle 
	 * tunnel/ethernet man in the middle
	 */
	struct sockaddr_ll send_ll;
	struct sj_config &runconfig;

	/* tunfd/netfd: file descriptor for I/O purpose */
	int tunfd;
	int netfd;
	
	/* flags sets for the two file descriptors */
	int tunfd_flags_blocking;
	int tunfd_flags_nonblocking;
	int netfd_flags_blocking;
	int netfd_flags_nonblocking;

        /* poll variables, two file descriptors */
        struct pollfd fds[2];
        int nfds;

	TCPTrack *conntrack;

	unsigned char pktbuf[MTU];
	int size;
	
	struct timespec timeout_with_outgoing_data_to_flush;
	struct timespec timeout_with_incoming_data_received;
	struct timespec maximum_timeout;

public:

	/* networkdown_condition express if the network is down and sniffjoke must be interrupted 
	 *	   --- but not killed!
	 */

	NetIO(sj_config &);
	~NetIO(void);
	void prepare_conntrack(TCPTrack *);
	void network_io(void);
};

#endif /* SJ_NETIO_H */
