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

#include "SniffJokeCli.h"

#include <errno.h>
#include <fcntl.h>
#include <poll.h>
#include <time.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <sys/un.h>
#include <sys/wait.h>

#include <cstdlib>

SniffJokeCli::SniffJokeCli(char* serveraddr, uint16_t serverport) :
	serveraddr(serveraddr),
	serverport(serverport)
{
}

void SniffJokeCli::send_command(const char *cmdstring)
{
	int sock;
	char rcv_buf[4096];
	struct sockaddr_in service_sin;	/* address of service */
	struct sockaddr_in from;	/* address used for receiving data */
	int rlen;
	
	
	/* Create a UNIX datagram socket for client */
	if ((sock = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP)) == -1) {
		printf("FATAL: unable to open UDP socket for connect to SniffJoke service: %s", strerror(errno));
		exit(0);
	}
	
	memset(&service_sin, 0x00, sizeof(service_sin));
	service_sin.sin_family = AF_INET;
	service_sin.sin_port = htons(serverport);
	
	if (!inet_aton(serveraddr, &service_sin.sin_addr)) {
		printf("Unable to accept hostname (%s): only IP address allow", serveraddr);
		return;
	}
	
	if (sendto(sock, cmdstring, strlen(cmdstring), 0, (const struct sockaddr *)&service_sin, sizeof(service_sin)) == -1) {
		printf("FATAL: unable to send message [%s] via %s:%d: %s", cmdstring, serveraddr, serverport, strerror(errno));
		return;
	}
	
        struct pollfd fd;
        fd.events = POLLIN;
        fd.fd = sock;
        	
	int nfds = poll(&fd, 1, 200);
	
	if(nfds == 1) {
		memset(rcv_buf, 0x00, sizeof(rcv_buf));
		int fromlen = sizeof(struct sockaddr_in);
		if ((rlen = (recvfrom(sock, rcv_buf, sizeof(rcv_buf), MSG_WAITALL, (sockaddr*)&from, (socklen_t *)&fromlen))) == -1) {
			printf("unable to receive from local socket: %s\n", strerror(errno));
			goto send_command_exit;
		}
	
		if (rlen == 0)
			printf("invalid command [%s] produces no answer. Verify with sniffjoke --help\n", cmdstring);
		else	/* the output */ 
			printf("<SniffJoke service>: %s\n", rcv_buf);
	} else {
		printf("timeout: sniffJoke is probably not running\n");
	}

send_command_exit:
	close(sock);
}
