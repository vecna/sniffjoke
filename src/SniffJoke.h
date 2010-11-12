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
#ifndef SJ_SNIFFJOKE_H
#define SJ_SNIFFJOKE_H

#include "Utils.h"
#include "UserConf.h"
#include "Process.h"
#include "NetIO.h"

#include <csignal>
#include <cstdio>
#include <memory>

#include <sys/types.h>
#include <pwd.h>
#include <grp.h>

using namespace std;

class SniffJoke {
private:
	auto_ptr<Process> proc;
	auto_ptr<UserConf> userconf;
	auto_ptr<NetIO> mitm;
	auto_ptr<HackPool> hack_pool;
	auto_ptr<TCPTrack> conntrack;

	pid_t service_pid;
	int listening_unix_socket;

	void kill_child();
	int bind_unixsocket();
	void handle_unixsocket(int srvsock, bool &alive);
	int recv_command(int sock, char *databuf, int bufsize, struct sockaddr *from, FILE *error_flow, const char *usermsg);	
	bool parse_port_weight(char *weightstr, Strength *Value);
public:
	SniffJoke(const struct sj_cmdline_opts &);
	void client(const char *);
	void server(bool, bool);
	void server_root_cleanup();
	void server_user_cleanup();
	void send_command(const char *cmdstring);
};

#endif /* SJ_SNIFFJOKE_H */
