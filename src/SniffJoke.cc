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

#include "SniffJoke.h"

#include <fcntl.h>
#include <sys/types.h>
#include <sys/un.h>
#include <sys/wait.h>

SniffJoke::SniffJoke(struct sj_cmdline_opts &opts) :
	opts(opts),
	userconf(opts),
	proc(opts),
	service_pid(0),
	alive(true)
{
	debug_setup(stdout);
	debug.log(VERBOSE_LEVEL, __func__);
}

void SniffJoke::run()
{
	switch (opts.process_type) {
		case SJ_SERVER_PROC:
			server();
			break;
		case SJ_CLIENT_PROC:
			client();
			break;
	}
}

void SniffJoke::client() {
	pid_t running_service_pid = proc.readPidfile();
	if (!running_service_pid) {
		debug.log(ALL_LEVEL, "warning: SniffJoke is not running, command %s ignored", opts.cmd_buffer);
		return;
	}

	proc.jail();
	proc.privilegesDowngrade();
	send_command(opts.cmd_buffer);

	return;
}

void SniffJoke::server() {

	pid_t old_service_pid = proc.readPidfile();
	if (old_service_pid != 0) {
		if (!opts.force_restart) {
			debug.log(ALL_LEVEL, "SniffJoke is already running, use --force or check --help");
			debug.log(ALL_LEVEL, "the pidfile %s contains the apparently running pid: %d", SJ_PIDFILE, old_service_pid);
			return;
		} else {
			debug.log(VERBOSE_LEVEL, "forcing exit of previous running service %d ...", old_service_pid);
			
			/* we have to do quite the same as in sniffjoke_server_cleanup,
			 * but relative to the service_pid read with readPidfile;
			 * here we can not use the waitpid because the process to kill it's not a child of us;
			 * we can use a sleep(2) instead. */
			kill(old_service_pid, SIGTERM);
			sleep(2);
			proc.unlinkPidfile();
			debug.log(ALL_LEVEL, "A new instance of SniffJoke is going running in background");
		}
	}

	if(!old_service_pid && opts.force_restart)
		debug.log(VERBOSE_LEVEL, "option --force ignore: not found a previously running SniffJoke");

	/* running the network setup before the background, for keep the software output visible on the console */
	userconf.network_setup();

	if (!userconf.running.active)
		debug.log(ALL_LEVEL, "SniffJoke is INACTIVE: use \"sniffjoke start\" command to start it");
	else
		debug.log(VERBOSE_LEVEL, "SniffJoke resumed as ACTIVE");

	if (!opts.go_foreground) {
		proc.background();

		/* Log Object must be reinitialized after background and before the chroot! */
		debug_setup(NULL);

		proc.isolation();
	}

	proc.writePidfile();
	
	/* the code flow reach here, SniffJoke is ready to instance network environment */
	mitm = auto_ptr<NetIO> (new NetIO(userconf.running));

        /* sigtrap handler mapped the same in both Sj processes */
        proc.sigtrapSetup(sigtrap);

	/* proc.detach: fork() into two processes, 
	   from now on the real configuration is the one mantained by the child */
	service_pid = proc.detach();

	/* this is the root privileges thread, need to run for restore the network
	 * environment in shutdown */
	if(service_pid) {
		int deadtrace;
		
		waitpid(service_pid, &deadtrace, WUNTRACED);
		
		if (WIFEXITED(deadtrace))
			debug.log(VERBOSE_LEVEL, "child %d WIFEXITED", service_pid);
		if (WIFSIGNALED(deadtrace))
			debug.log(VERBOSE_LEVEL, "child %d WIFSIGNALED", service_pid);
		if (WIFSTOPPED(deadtrace))
			debug.log(VERBOSE_LEVEL, "child %d WIFSTOPPED", service_pid);

		debug.log(DEBUG_LEVEL, "child %d died, going to shutdown", service_pid);

	} else {
		
		/* loading the plugins used for tcp hacking, MUST be done before proc.jail() */
		hack_pool = auto_ptr<HackPool> (new HackPool(userconf.running.enabler));

		/* proc.jail: chroot + userconf.running.chrooted = true */
		proc.jail();
		userconf.chroot_status = true;

		proc.privilegesDowngrade();

		conntrack = auto_ptr<TCPTrack> (new TCPTrack(userconf.running, *hack_pool));
		mitm->prepare_conntrack(conntrack.get());

		listening_unix_socket = bind_unixsocket();

		/* main block */
		while (alive) {

			proc.sigtrapDisable();

			mitm->network_io();
			mitm->queue_flush();

			handle_unixsocket(listening_unix_socket, alive);

			proc.sigtrapEnable();
		}
	}
}

SniffJoke::~SniffJoke()
{
	debug.log(DEBUG_LEVEL, "%s [process %d, role %s]", __func__, getpid(), 
		opts.process_type == SJ_SERVER_PROC ? "service" : "client" );

	switch (opts.process_type) {
		case SJ_SERVER_PROC:
			if (getuid() || geteuid()) {
				server_user_cleanup();
			} else {
				if(service_pid != 0) {
					server_root_cleanup();
				}
					
			}	
			break;
		case SJ_CLIENT_PROC:
			client_cleanup();
			break;
	}

	debug_cleanup();
}

void SniffJoke::server_root_cleanup()
{
	debug.log(VERBOSE_LEVEL, "server_root_cleanup() %d", service_pid);
	kill(service_pid, SIGTERM);
	waitpid(service_pid, NULL, WUNTRACED);
	proc.unlinkPidfile();
}

void SniffJoke::server_user_cleanup()
{
	debug.log(VERBOSE_LEVEL, "client_user_cleanup()");
}

void SniffJoke::client_cleanup() {

}

int SniffJoke::bind_unixsocket()
{
	const char *SniffJoke_socket_path = SJ_SERVICE_UNIXSOCK; 
	struct sockaddr_un sjsrv;
	int sock;

	if ((sock = socket(AF_UNIX, SOCK_DGRAM, 0)) == -1) {
		debug.log(ALL_LEVEL, "FATAL: unable to open unix socket (%s): %s", SJ_SERVICE_UNIXSOCK, strerror(errno));
		SJ_RUNTIME_EXCEPTION();
	}

	memset(&sjsrv, 0x00, sizeof(sjsrv));
	sjsrv.sun_family = AF_UNIX;
	memcpy(sjsrv.sun_path, SniffJoke_socket_path, strlen(SniffJoke_socket_path));

	if (!access(SniffJoke_socket_path, F_OK)) {
		if (unlink(SniffJoke_socket_path)) {
			debug.log(ALL_LEVEL, "FATAL: unable to unlink %s before using as unix socket: %s", 
				SniffJoke_socket_path, strerror(errno));
			SJ_RUNTIME_EXCEPTION();
		}
	}
								
	if (bind(sock, (struct sockaddr *)&sjsrv, sizeof(sjsrv)) == -1) {
		close(sock);
		debug.log(ALL_LEVEL, "FATAL ERROR: unable to bind unix socket %s: %s", 
			 SniffJoke_socket_path, strerror(errno)
		);
		SJ_RUNTIME_EXCEPTION();
	}

	if (fcntl(sock, F_SETFL, O_NONBLOCK) == -1) {
		close(sock);
		debug.log(ALL_LEVEL, "FATAL ERROR: unable to set non blocking unix socket %s: %s",
			SniffJoke_socket_path, strerror(errno)
		);
		SJ_RUNTIME_EXCEPTION();
	}
	debug.log(VERBOSE_LEVEL, "Successful binding of unix socket in %s", SniffJoke_socket_path);

	return sock;
}

void SniffJoke::handle_unixsocket(int srvsock, bool &alive)
{
	char r_command[MEDIUMBUF], *output = NULL, *internal_buf = NULL;
	int rlen;
	struct sockaddr_un fromaddr;

	if ((rlen = recv_command(srvsock, r_command, MEDIUMBUF, (struct sockaddr *)&fromaddr, NULL, "from the command receiving engine")) == -1) 
		SJ_RUNTIME_EXCEPTION();

	if (!rlen)
		return;

	debug.log(VERBOSE_LEVEL, "received command from the client: %s", r_command);

	if (!memcmp(r_command, "start", strlen("start"))) {
		output = userconf.handle_cmd_start();
	} else if (!memcmp(r_command, "stop", strlen("stop"))) {
		output = userconf.handle_cmd_stop();
	} else if (!memcmp(r_command, "quit", strlen("quit"))) {
		output = userconf.handle_cmd_quit();
		alive = false;
	} else if (!memcmp(r_command, "saveconfig", strlen("saveconfig"))) {
		output = userconf.handle_cmd_saveconfig();
	} else if (!memcmp(r_command, "stat", strlen("stat"))) {
		output = userconf.handle_cmd_stat();
	} else if (!memcmp(r_command, "info", strlen("info"))) {
		output = userconf.handle_cmd_info();
	} else if (!memcmp(r_command, "showport", strlen("showport"))) {
		output = userconf.handle_cmd_showport();
	} else if (!memcmp(r_command, "set", strlen("set"))) {
		int start_port, end_port;
		Strength setValue;
		char weight[MEDIUMBUF];

		sscanf(r_command, "set %d %d %s", &start_port, &end_port, weight);

		if (start_port < 0 || start_port > PORTNUMBER || end_port < 0 || end_port > PORTNUMBER)
			goto handle_set_error;

		if (!parse_port_weight(weight, &setValue))
			goto handle_set_error;

		if (start_port > end_port)
			goto handle_set_error;

		output = userconf.handle_cmd_set(start_port, end_port, setValue);

handle_set_error:
		if(output == NULL) {
			internal_buf = (char *)malloc(MEDIUMBUF);
			snprintf(internal_buf, MEDIUMBUF, "invalid set command: [startport] [endport] VALUE\n"\
				"startport and endport need to be less than %d\n"\
				"startport nedd to be less or equal endport\n"\
				"value would be: none|light|normal|heavy\n", PORTNUMBER);
			debug.log(ALL_LEVEL, "%s", internal_buf);
			output = internal_buf;
		}
	} else if (!memcmp(r_command, "clear", strlen("clear"))) {
		Strength clearValue = NONE;
		output = userconf.handle_cmd_set(0, PORTNUMBER, clearValue);
	} else if (!memcmp(r_command, "loglevel", strlen("loglevel")))  {
		int loglevel;

		sscanf(r_command, "loglevel %d", &loglevel);
		if (loglevel < 0 || loglevel > PACKETS_DEBUG) {
			internal_buf = (char *)malloc(MEDIUMBUF);
			snprintf(internal_buf, MEDIUMBUF, "invalid log value: %d, must be > 0 and < than %d", loglevel, PACKETS_DEBUG);
			debug.log(ALL_LEVEL, "%s", internal_buf);
			output = internal_buf;
		} else {
			output = userconf.handle_cmd_loglevel(loglevel);
		}
	} else {
		debug.log(ALL_LEVEL, "wrong command %s", r_command);
	}

	/* send the answer message to the client */
	if(output != NULL) 
		sendto(srvsock, output, strlen(output), 0, (struct sockaddr *)&fromaddr, sizeof(fromaddr));

	if (internal_buf != NULL)
		free(internal_buf);
}

void SniffJoke::send_command(const char *cmdstring)
{
	int sock;
	char received_buf[HUGEBUF];
	struct sockaddr_un servaddr;/* address of server */
	struct sockaddr_un clntaddr;/* address of client */
	struct sockaddr_un from; /* address used for receiving data */
	int rlen;
	
	/* Create a UNIX datagram socket for client */
	if ((sock = socket(AF_UNIX, SOCK_DGRAM, 0)) == -1) {
		debug.log(ALL_LEVEL, "FATAL: unable to open UNIX/DGRAM socket for connect to SniffJoke service: %s", strerror(errno));
		exit(0);
	}

	/*
	 * Client will bind to an address so the server/service will get an address in its recvfrom call and use it to
	 * send data back to the client.  
	 */
	memset(&clntaddr, 0x00, sizeof(clntaddr));
	clntaddr.sun_family = AF_UNIX;
	strcpy(clntaddr.sun_path, SJ_CLIENT_UNIXSOCK);

	unlink(SJ_CLIENT_UNIXSOCK);
	if (bind(sock, (const sockaddr *)&clntaddr, sizeof(clntaddr)) == -1) {
		debug.log(ALL_LEVEL, "FATAL: unable to bind client to %s: %s", SJ_CLIENT_UNIXSOCK, strerror(errno));
		SJ_RUNTIME_EXCEPTION();
	}

	/* Set up address structure for server/service socket */
	memset(&servaddr, 0x00, sizeof(servaddr));
	servaddr.sun_family = AF_UNIX;
	strcpy(servaddr.sun_path, SJ_SERVICE_UNIXSOCK);

	if (sendto(sock, cmdstring, strlen(cmdstring), 0, (const struct sockaddr *)&servaddr, sizeof(servaddr)) == -1) {
		debug.log(ALL_LEVEL, "FATAL: unable to send message [%s] via %s: %s - Rembember: what SniffJoke run with --chroot-dir or --config parms, you need to pass the same options in the client (the unix socket used reside under chroot dir)", cmdstring, SJ_SERVICE_UNIXSOCK, strerror(errno));
		SJ_RUNTIME_EXCEPTION();
	}

	/* We receive a max of HUGEBUF -1 saving us from segfault during printf */
	if ((rlen = recv_command(sock, received_buf, HUGEBUF, (struct sockaddr *)&from, stdout, "from the command sending engine")) == -1)
		SJ_RUNTIME_EXCEPTION();

	if (rlen == 0)
		debug.log(ALL_LEVEL, "unreceived response for the command [%s]", cmdstring);
	else	/* the output */ 
		printf("<SniffJoke service>: %s", received_buf);
	
	close(sock);
}

int SniffJoke::recv_command(int sock, char *databuf, int bufsize, struct sockaddr *from, FILE *error_flow, const char *usermsg)
{
	memset(databuf, 0x00, bufsize);

	/* we receive up to bufsize -1 having databuf[bufsize] = 0 and saving us from future segfaults */

	int fromlen = sizeof(struct sockaddr_un), ret;

	if ((ret = recvfrom(sock, databuf, bufsize, 0, from, (socklen_t *)&fromlen)) == -1) 
	{
		if (errno == EAGAIN || errno == EWOULDBLOCK) {
			return 0;
		}

		debug.log(ALL_LEVEL, "unable to receive local socket: %s: %s", usermsg, strerror(errno));
	}

	return ret;
}

bool SniffJoke::parse_port_weight(char *weightstr, Strength *value)
{
	struct parsedata {
		const char *keyword;
		const int keylen;
		Strength equiv;
	};
#define keywordToParse	4
	struct parsedata wParse[] = {
		{ "none", 	strlen("none"), 	NONE },
		{ "light", 	strlen("light"), 	LIGHT },
		{ "normal", 	strlen("normal"), 	NORMAL },
		{ "heavy", 	strlen("heavy"), 	HEAVY }
	};
	int i;

	for(i = 0; i < keywordToParse; i++) {
		if(!strncasecmp(weightstr, wParse[i].keyword, wParse[i].keylen)) {
			*value = wParse[i].equiv;
			return true;
		}
	}
	return false;
}


void SniffJoke::debug_setup(FILE *forcedoutput) const
{
	debug.debuglevel = opts.debug_level;

	/* when sniffjoke start force the output to be stdout */
	if(forcedoutput != NULL) {
		debug.logstream = forcedoutput;
		return;
	}
	
	if (opts.process_type == SJ_SERVER_PROC && !opts.go_foreground) {
		
		/* Logfiles are used only by a Sniffjoke SERVER runnning in background */
		
		if ((debug.logstream = fopen(opts.logfname, "a+")) == NULL) {
			debug.log(ALL_LEVEL, "FATAL ERROR: unable to open %s: %s", opts.logfname, strerror(errno));
			SJ_RUNTIME_EXCEPTION();
		} else {
			debug.log(DEBUG_LEVEL, "opened log file %s", opts.logfname);
		}	
	
		if (debug.debuglevel >= PACKETS_DEBUG) {
			if ((debug.packet_logstream = fopen(opts.logfname_packets, "a+")) == NULL) {
				debug.log(ALL_LEVEL, "FATAL ERROR: unable to open %s: %s", opts.logfname_packets, strerror(errno));
				SJ_RUNTIME_EXCEPTION();
			} else {
				debug.log(ALL_LEVEL, "opened for packets debug: %s successful", opts.logfname_packets);
			}
		}

		if (debug.debuglevel >= SESSION_DEBUG) {
			if ((debug.session_logstream = fopen(opts.logfname_sessions, "a+")) == NULL) {
				debug.log(ALL_LEVEL, "FATAL ERROR: unable to open %s: %s", opts.logfname_sessions, strerror(errno));
				SJ_RUNTIME_EXCEPTION();
			} else {
				debug.log(ALL_LEVEL, "opened for hacks debug: %s successful", opts.logfname_sessions);
			}
		}
	} else if(opts.process_type == SJ_CLIENT_PROC) {
		debug.logstream = stdout;
		debug.log(DEBUG_LEVEL, "client write a verbose output on stdout, whenever a block happen, use ^c");
	} else /* opts.go_foreground */ {
		debug.logstream = stdout;
		debug.log(ALL_LEVEL, "forground logging enable, use ^c for quit SniffJoke");
	}
}

void SniffJoke::debug_cleanup() const
{
	if(debug.logstream != NULL && debug.logstream != stdout)
		fclose(debug.logstream);
	if(debug.packet_logstream != NULL && debug.packet_logstream != stdout)
		fclose(debug.packet_logstream);
	if(debug.session_logstream != NULL && debug.session_logstream != stdout)
		fclose(debug.session_logstream);
}
