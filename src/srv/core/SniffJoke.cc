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
#include <time.h>
#include <sys/types.h>
#include <sys/un.h>
#include <sys/wait.h>

SniffJoke::SniffJoke(struct sj_cmdline_opts &opts) :
	alive(true),
	opts(opts),
	userconf(opts, alive),
	proc(userconf.runconfig),
	service_pid(0)
{
	debug_setup(stdout);
	debug.log(VERBOSE_LEVEL, __func__);
}

SniffJoke::~SniffJoke()
{
	if (getuid() || geteuid()) {
		debug.log(DEBUG_LEVEL, "Service with users privileges: %s [%d]", __func__, getpid());
		server_user_cleanup();
	} else {
		debug.log(DEBUG_LEVEL, "Service with root privileges: %s [%d]", __func__, getpid());
		server_root_cleanup();
	}	
	/* closing the log files */
	debug_cleanup();
}

void SniffJoke::run()
{
	pid_t old_service_pid = proc.readPidfile();
	if (old_service_pid != 0) {
		if (!opts.force_restart) {
			debug.log(ALL_LEVEL, "SniffJoke is already runconfig, use --force or check --help");
			debug.log(ALL_LEVEL, "the pidfile %s contains the apparently runconfig pid: %d", SJ_PIDFILE, old_service_pid);
			return;
		} else {
			debug.log(VERBOSE_LEVEL, "forcing exit of previous runconfig service %d ...", old_service_pid);
			
			/* we have to do quite the same as in sniffjoke_server_cleanup,
			 * but relative to the service_pid read with readPidfile;
			 * here we can not use the waitpid because the process to kill it's not a child of us;
			 * we can use a sleep(2) instead. */
			kill(old_service_pid, SIGTERM);
			sleep(2);
			proc.unlinkPidfile();
			debug.log(ALL_LEVEL, "A new instance of SniffJoke is going runconfig in background");
		}
	}

	if (!old_service_pid && opts.force_restart)
		debug.log(VERBOSE_LEVEL, "option --force ignore: not found a previously runconfig SniffJoke");

	/* runconfig the network setup before the background, for keep the software output visible on the console */
	userconf.network_setup();

	if (!userconf.runconfig.active)
		debug.log(ALL_LEVEL, "SniffJoke is INACTIVE: use \"sniffjoke start\" command to start it");
	else
		debug.log(VERBOSE_LEVEL, "SniffJoke resumed as ACTIVE");

	if (!opts.go_foreground) {
		proc.background();

		/* Log Object must be reinitialized after background and before the chroot! */
		debug_setup(NULL);

		proc.isolation();
	}
	
	/* the code flow reach here, SniffJoke is ready to instance network environment */
	mitm = auto_ptr<NetIO> (new NetIO(userconf.runconfig));

        /* sigtrap handler mapped the same in both Sj processes */
        proc.sigtrapSetup(sigtrap);

	/* proc.detach: fork() into two processes, 
	   from now on the real configuration is the one mantained by the child */
	service_pid = proc.detach();

	/* this is the root privileges thread, need to run for restore the network
	 * environment in shutdown */
	if (service_pid) {
		int deadtrace;
		
		proc.writePidfile();
		if(waitpid(service_pid, &deadtrace, WUNTRACED) > 0) {
		
			if (WIFEXITED(deadtrace))
				debug.log(VERBOSE_LEVEL, "child %d WIFEXITED", service_pid);
			if (WIFSIGNALED(deadtrace))
				debug.log(VERBOSE_LEVEL, "child %d WIFSIGNALED", service_pid);
			if (WIFSTOPPED(deadtrace))
				debug.log(VERBOSE_LEVEL, "child %d WIFSTOPPED", service_pid);
		} else {
			debug.log(VERBOSE_LEVEL, "child waitpid failed with: %s", strerror(errno));
		}

		debug.log(DEBUG_LEVEL, "child %d died, going to shutdown", service_pid);

	} else {
		
		/* loading the plugins used for tcp hacking, MUST be done before proc.jail() */
		hack_pool = auto_ptr<HackPool> (new HackPool(userconf.runconfig));

		/* proc.jail: chroot + userconf.runconfig.chrooted = true */
		proc.jail();
		userconf.chroot_status = true;

		proc.privilegesDowngrade();

		sessiontrack_map = auto_ptr<SessionTrackMap> (new SessionTrackMap);
		ttlfocus_map = auto_ptr<TTLFocusMap> (new TTLFocusMap(userconf.runconfig.ttlfocuscache_file, userconf.runconfig.location));
		conntrack = auto_ptr<TCPTrack> (new TCPTrack(userconf.runconfig, *hack_pool, *sessiontrack_map, *ttlfocus_map));

		mitm->prepare_conntrack(conntrack.get());

		admin_socket_setup();

		/* main block */
		while (alive) {

			sj_clock = time(NULL);

			proc.sigtrapDisable();

			mitm->network_io();

			admin_socket_handle();
			
			proc.sigtrapEnable();
		}
	}
}

void SniffJoke::debug_setup(FILE *forcedoutput) const
{
	debug.debuglevel = userconf.runconfig.debug_level;

	/* when sniffjoke start force the output to be stdout */
	if (forcedoutput != NULL) {
		debug.logstream = forcedoutput;
		return;
	}

	if (opts.process_type == SJ_SERVER_PROC && !opts.go_foreground) {
		/* Logfiles are used only by a Sniffjoke SERVER runnning in background */
		if(!debug.resetLevel(userconf.runconfig.logfname, userconf.runconfig.logfname_sessions, userconf.runconfig.logfname_packets))
			SJ_RUNTIME_EXCEPTION("Error in opening log files");
	} 
	else if (opts.process_type == SJ_CLIENT_PROC) {
		debug.logstream = stdout;
		debug.log(DEBUG_LEVEL, "client write a verbose output on stdout, whenever a block happen, use ^c");
	} 
	else /* userconf.runconfig.go_foreground */ {
		debug.logstream = stdout;
		debug.log(ALL_LEVEL, "forground logging enable, use ^c for quit SniffJoke");
	}
}

/* this function must not close the FILE *desc, because in the destructor of the
 * auto_ptr some debug call will be present. It simple need to flush the FILE,
 * and the descriptor are closed with the process, after. */
void SniffJoke::debug_cleanup()
{
	if (debug.logstream != NULL && debug.logstream != stdout)
		fflush(debug.logstream);
	if (debug.packet_logstream != NULL && debug.packet_logstream != stdout)
		fflush(debug.packet_logstream);
	if (debug.session_logstream != NULL && debug.session_logstream != stdout)
		fflush(debug.session_logstream);
}

void SniffJoke::server_root_cleanup()
{
	if (service_pid) {
		debug.log(VERBOSE_LEVEL, "server_root_cleanup() %d", service_pid);
		kill(service_pid, SIGTERM);
		waitpid(service_pid, NULL, WUNTRACED);
	}

	proc.unlinkPidfile();
}

void SniffJoke::server_user_cleanup()
{
	debug.log(VERBOSE_LEVEL, "client_user_cleanup()");
	userconf.dump();
}

void SniffJoke::admin_socket_setup()
{
	int tmp;
	struct sockaddr_in in_service;

	if ((tmp = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP)) == -1) {
		debug.log(ALL_LEVEL, "FATAL: unable to open UDP socket: %s", strerror(errno));
		SJ_RUNTIME_EXCEPTION("");
	}

	memset(&in_service, 0x00, sizeof(in_service));
	/* here we are running under chroot, resolution will not work without /etc/hosts and /etc/resolv.conf */
	if (!inet_aton(userconf.runconfig.admin_address, &in_service.sin_addr)) {
		debug.log(ALL_LEVEL, "Unable to accept hostname (%s): only IP address allow", userconf.runconfig.admin_address);
		SJ_RUNTIME_EXCEPTION("");
	}
	in_service.sin_family = AF_INET;
	in_service.sin_port = htons(userconf.runconfig.admin_port);

	if (bind(tmp, (struct sockaddr *)&in_service, sizeof(in_service)) == -1) {
		close(tmp);
		debug.log(ALL_LEVEL, "FATAL ERROR: unable to bind UDP socket %s:%d: %s", 
			 userconf.runconfig.admin_address, ntohs(in_service.sin_port), strerror(errno)
		);
		SJ_RUNTIME_EXCEPTION("");
	}

	admin_socket_flags_blocking = fcntl(tmp, F_GETFL);
	admin_socket_flags_nonblocking = admin_socket_flags_blocking | O_NONBLOCK;

	if (fcntl(tmp, F_SETFL, admin_socket_flags_nonblocking) == -1) {
		close(tmp);
		debug.log(ALL_LEVEL, "FATAL ERROR: unable to set non blocking administration socket: %s",
			strerror(errno)
		);
		SJ_RUNTIME_EXCEPTION("");
	}

	admin_socket = tmp;
}

void SniffJoke::admin_socket_handle()
{
	char r_buf[MEDIUMBUF];
	char* output = NULL;
	struct sockaddr_in fromaddr;

	memset(r_buf, 0x00, sizeof(r_buf));
	int fromlen = sizeof(struct sockaddr_in);
	if ((recvfrom(admin_socket, r_buf, sizeof(r_buf), 0, (sockaddr*)&fromaddr, (socklen_t *)&fromlen)) == -1) {
		if (errno == EAGAIN || errno == EWOULDBLOCK) {
			return;
		}
		debug.log(ALL_LEVEL, "unable to receive from local socket: %s", strerror(errno));
		SJ_RUNTIME_EXCEPTION("");
	}

	debug.log(VERBOSE_LEVEL, "received command from the client: %s", r_buf);

	output = userconf.handle_cmd(r_buf);

	/* checking if the command require SniffJoke class interaction (loglevel change), these are the
	 * command that could cause an interruption of the service - require to be modify the "char *output"
	 * with the appropriate error - TODO ATM */
	if(debug.debuglevel != userconf.runconfig.debug_level) 
	{
		debug.debuglevel = userconf.runconfig.debug_level;

		if(!debug.resetLevel(	basename(userconf.runconfig.logfname),
					basename(userconf.runconfig.logfname_sessions),
					basename(userconf.runconfig.logfname_packets)
		))
			SJ_RUNTIME_EXCEPTION("Changing logfile settings");
	}

	/* send the answer message to the client */
	if (output != NULL) {
		fcntl(admin_socket, F_SETFL, admin_socket_flags_blocking);
		sendto(admin_socket, output, strlen(output), 0, (struct sockaddr *)&fromaddr, sizeof(fromaddr));
		fcntl(admin_socket, F_SETFL, admin_socket_flags_nonblocking);
	}
}

int SniffJoke::recv_command(int sock, char *databuf, int bufsize, struct sockaddr *from, FILE *error_flow, const char *usermsg)
{
	memset(databuf, 0x00, bufsize);

	int fromlen = sizeof(struct sockaddr_in), ret;

	if ((ret = recvfrom(sock, databuf, bufsize, MSG_WAITALL, from, (socklen_t *)&fromlen)) == -1)
	{
		if (errno == EAGAIN || errno == EWOULDBLOCK)
			return 0;

		debug.log(ALL_LEVEL, "unable to receive local socket: %s: %s", usermsg, strerror(errno));
	}

	return ret;
}
