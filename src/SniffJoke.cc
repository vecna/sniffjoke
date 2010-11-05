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
#include "hardcoded-defines.h"

#include "UserConf.h"
#include "Process.h"
#include "Utils.h"
#include "NetIO.h"
#include "TCPTrack.h"

#include <csignal>
#include <fcntl.h>
#include <getopt.h>
#include <sys/un.h>
#include <sys/param.h>

/* process configuration, data struct defined in sniffjoke.h */
static struct sj_useropt useropt;

/* Sniffjoke networking and feature configuration */
static UserConf *sjconf = NULL;
/* Sniffjoke man in the middle class and functions */
static NetIO *mitm = NULL;
/* Sniffjoke connection tracking class and functions */
static TCPTrack *conntrack = NULL;
/* process tracking, handling, killing, breeding, ecc... */
static Process *SjProc = NULL;

#define SNIFFJOKE_HELP_FORMAT \
	"%s [command] or %s --options:\n"\
	" --debug [level 1-6]\tset up verbosoty level [default: %d]\n"\
	"\t\t\t1: suppress log, 2: common, 3: verbose, 4: debug, 5: session 6: packets\n"\
	" --logfile [file]\tset a logfile, [default: %s%s]\n"\
	" --user [username]\tdowngrade priviledge to the specified user [default: %s]\n"\
	" --group [groupname]\tdowngrade priviledge to the specified group [default: %s]\n"\
	" --chroot-dir [dir]\truns chroted into the specified dir [default: %s]\n"\
	" --force\t\tforce restart if sniffjoke service\n"\
	" --foreground\t\trunning in foreground [default:background]\n"\
	" --config [filename]\tconfig file [default: %s%s]\n"\
	" --enabler [filename]\tplugins enabler file [default: %s]\n"\
	" --version\t\tshow sniffjoke version\n"\
	" --help\t\t\tshow this help (special --help hacking)\n\n"\
	"while sniffjoke is running, you should send one of those commands as command line argument:\n"\
	" start\t\t\tstart sniffjoke hijacking/injection\n"\
	" stop\t\t\tstop sniffjoke (but remain tunnel interface active)\n"\
	" quit\t\t\tstop sniffjoke, save config, abort the service\n"\
	" stat\t\t\tget statistics about sniffjoke configuration and network\n\n"\
	" info\t\t\tget massive info about sniffjoke internet stats\n\n"\
	" set start end value\tset per tcp ports the strongness of injection\n"\
	" \t\t\tthe values are: [heavy|normal|light|none]\n"\
	" \t\t\texample: sniffjoke set 22 80 heavy\n"\
	" clear\t\t\talias to \"set 1 65535 none\"\n"\
	" showport\t\tshow TCP ports strongness of injection\n"\
	" loglevel\t\t[1-6] change the loglevel\n\n"\
	"\t\t\thttp://www.delirandom.net/sniffjoke\n"

static void sj_help(const char *pname, const char *basedir)
{
	printf(SNIFFJOKE_HELP_FORMAT, pname, pname, DEFAULT_DEBUG_LEVEL, 
		basedir, LOGFILE, 
		DROP_USER, DROP_GROUP, 
		basedir, basedir, CONF_FILE, PLUGINSENABLER);
}

static void sj_version(const char *pname)
{
	printf("%s %s\n", SW_NAME, SW_VERSION);
}

static void ForcePreviousQuit(pid_t pid)
{
	/* the function return when the process is dead */  
	bool dead = false;
	int killret;

	/* kill! */
	killret = kill(pid, SIGTERM);
	
	while (!dead) {
		if (!killret)
			usleep(50000);
		else if (errno == EPERM) {
			internal_log(NULL, ALL_LEVEL, "you have not privileges to kill process (%d)", pid);
			exit(0);
		} else /* (errno == ESRCH) */ {
			dead = true;
			internal_log(NULL, ALL_LEVEL, "Termination of process: (%d) success (process is dead)", pid);
		}
		
		/* test if the pid is running again */
		killret = kill(pid, SIGUSR1);
	}
}

static void sj_sigtrap(int signal) 
{
	if (signal)
		internal_log(NULL, ALL_LEVEL, "received signal %d, pid %d cleaning sniffjoke objects...", signal, getpid());
		
	/* different way for closing sniffjoke if the signal come from the father or the child */
	if(getuid()) {
		SjProc->ServiceChildClose();
	} 
	else {
		if (mitm != NULL)
			delete mitm;
		if (conntrack != NULL)
			delete conntrack;
		if (sjconf != NULL)
			delete sjconf;

		SjProc->unlinkPidfile();
		SjProc->ServiceFatherClose();

		/* ServiceFatherClose don't exit, but verify that the child is die too, because
		 * is easy for the exiting child be notify in the father, but if the father receive 
		 * a ^C (foreground) or a SIGTERM, the child must be terminated here
		 */
		kill(0, SIGTERM);
		usleep(50000);
		exit(0);
	}
}

/* internal routine called in client_send_command and read_unixsock */
static int service_listener(int sock, char *databuf, int bufsize, struct sockaddr *from, FILE *error_flow, const char *usermsg)
{
	memset(databuf, 0x00, bufsize);

	/* we receive up to bufsize -1 having databuf[bufsize] = 0 and saving us from future segfaults */

	int fromlen = sizeof(struct sockaddr_un), ret;

	if ((ret = recvfrom(sock, databuf, bufsize, 0, from, (socklen_t *)&fromlen)) == -1) 
	{
		if (errno == EAGAIN || errno == EWOULDBLOCK) {
			return 0;
		}

		internal_log(error_flow, ALL_LEVEL, "unable to receive local socket: %s: %s", usermsg, strerror(errno));
	}

	return ret;
}

static int sj_bind_unixsocket() 
{
	const char *sniffjoke_socket_path = SJ_SERVICE_UNIXSOCK; 
	struct sockaddr_un sjsrv;
	int sock;

	if ((sock = socket(AF_UNIX, SOCK_DGRAM, 0)) == -1) {
		internal_log(NULL, ALL_LEVEL, "FATAL: unable to open unix socket (%s): %s", SJ_SERVICE_UNIXSOCK, strerror(errno));
		SjProc->ServiceFatherClose();
	}

	memset(&sjsrv, 0x00, sizeof(sjsrv));
	sjsrv.sun_family = AF_UNIX;
	memcpy(sjsrv.sun_path, sniffjoke_socket_path, strlen(sniffjoke_socket_path));

	if (!access(sniffjoke_socket_path, F_OK)) {
		if (unlink(sniffjoke_socket_path)) {
			internal_log(NULL, ALL_LEVEL, "FATAL: unable to unlink %s before using as unix socket: %s", 
				sniffjoke_socket_path, strerror(errno));
			SjProc->ServiceFatherClose();
		}
	}
								
	if (bind(sock, (struct sockaddr *)&sjsrv, sizeof(sjsrv)) == -1) {
		close(sock);
		internal_log(NULL, ALL_LEVEL, "FATAL ERROR: unable to bind unix socket %s: %s", 
			 sniffjoke_socket_path, strerror(errno)
		);
		delete sjconf;
		delete mitm;
		SjProc->ServiceFatherClose();
	}

	if (fcntl(sock, F_SETFL, O_NONBLOCK) == -1) {
		close(sock);
		internal_log(NULL, ALL_LEVEL, "FATAL ERROR: unable to set non blocking unix socket %s: %s",
			sniffjoke_socket_path, strerror(errno)
		);

		SjProc->ServiceFatherClose();
	}
	internal_log(NULL, VERBOSE_LEVEL, "Successful binding of unix socket in %s", sniffjoke_socket_path);

	return sock;
}

/* function used in in order to receive command and modify the running conf, display stats and so on */
static void read_unixsock(int srvsock, UserConf *confobj)
{
	char r_command[MEDIUMBUF], *output =NULL, *internal_buf =NULL;
	int rlen;
	struct sockaddr_un fromaddr;

	if ((rlen = service_listener(srvsock, r_command, MEDIUMBUF, (struct sockaddr *)&fromaddr, NULL, "from the command receiving engine")) == -1) 
		raise(SIGTERM);

	if (!rlen)
		return;

	internal_log(NULL, VERBOSE_LEVEL, "received command from the client: %s", r_command);

	if (!memcmp(r_command, "stat", strlen("stat"))) {
		output = sjconf->handle_cmd_stat();
	} else if (!memcmp(r_command, "start", strlen("start"))) {
		output = sjconf->handle_cmd_start();
	} else if (!memcmp(r_command, "stop", strlen("stop"))) {
		output = sjconf->handle_cmd_stop();
	} else if (!memcmp(r_command, "quit", strlen("quit"))) {
		output = sjconf->handle_cmd_quit();
	} else if (!memcmp(r_command, "info", strlen("info"))) {
		output = sjconf->handle_cmd_info();
	} else if (!memcmp(r_command, "set", strlen("set"))) {
		int start_port, end_port, value;

		sscanf(r_command, "set %d %d %d", &start_port, &end_port, &value);

		if (start_port < 0 || start_port > PORTNUMBER || end_port < 0 || end_port > PORTNUMBER || 
			value < 0 || value >= 0x05) 
		{
			internal_buf = (char *)malloc(MEDIUMBUF);
			snprintf(internal_buf, MEDIUMBUF, "invalid port, %d or %d, must be > 0 and < %d",
				start_port, end_port, PORTNUMBER);
			internal_log(NULL, ALL_LEVEL, "%s", internal_buf);
			output = internal_buf;
		}
		else {
			output = sjconf->handle_cmd_set(start_port, end_port, value);
		}
	} else if (!memcmp(r_command, "clear", strlen("clear"))) {
		output = sjconf->handle_cmd_set(1, PORTNUMBER, NONE);
	} else if (!memcmp(r_command, "showport", strlen("showport"))) {
		output = sjconf->handle_cmd_showport();
	} else if (!memcmp(r_command, "loglevel", strlen("loglevel")))  {
		int loglevel;

		sscanf(r_command, "loglevel %d", &loglevel);
		if (loglevel < 0 || loglevel > PACKETS_DEBUG) {
			internal_buf = (char *)malloc(MEDIUMBUF);
			snprintf(internal_buf, MEDIUMBUF, "invalid log value: %d, must be > 0 and < than %d", loglevel, PACKETS_DEBUG);
			internal_log(NULL, ALL_LEVEL, "%s", internal_buf);
			output = internal_buf;
		} else {
			output = sjconf->handle_cmd_log(loglevel);
		}
	} else {
		internal_log(NULL, ALL_LEVEL, "wrong command %s", r_command);
	}

	/* send the answer message to the client */
	if (output != NULL)
		sendto(srvsock, output, strlen(output), 0, (struct sockaddr *)&fromaddr, sizeof(fromaddr));

	if (internal_buf != NULL)
		free(internal_buf);
}

static void client_send_command(char *cmdstring)
{
	int sock;
	char received_buf[HUGEBUF];
	struct sockaddr_un servaddr;/* address of server */
	struct sockaddr_un clntaddr;/* address of client */
	struct sockaddr_un from; /* address used for receiving data */
	int rlen;
	
	/* Create a UNIX datagram socket for client */
	if ((sock = socket(AF_UNIX, SOCK_DGRAM, 0)) == -1) {
		internal_log(NULL, ALL_LEVEL, "FATAL: unable to open UNIX/DGRAM socket for connect to sniffjoke service: %s", strerror(errno));
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
		internal_log(NULL, ALL_LEVEL, "FATAL: unable to bind client to %s: %s", SJ_CLIENT_UNIXSOCK, strerror(errno));
		exit(0);
	}

	/* Set up address structure for server/service socket */
	memset(&servaddr, 0x00, sizeof(servaddr));
	servaddr.sun_family = AF_UNIX;
	strcpy(servaddr.sun_path, SJ_SERVICE_UNIXSOCK);

	if (sendto(sock, cmdstring, strlen(cmdstring), 0, (const struct sockaddr *)&servaddr, sizeof(servaddr)) == -1) {
		internal_log(NULL, ALL_LEVEL, "FATAL: unable to send message [%s] via %s: %s - Rembember: what sniffjoke run with --chroot-dir or --config parms, you need to pass the same options in the client (the unix socket used reside under chroot dir)", cmdstring, SJ_SERVICE_UNIXSOCK, strerror(errno));
		exit(0);
	}

	/* We receive a max of HUGEBUF -1 saving us from segfault during printf */
	if ((rlen = service_listener(sock, received_buf, HUGEBUF, (struct sockaddr *)&from, stdout, "from the command sending engine")) == -1) 
		exit(0); 

	if (rlen == 0)
		internal_log(NULL, ALL_LEVEL, "unreceived response for the command [%s]", cmdstring);
	else	/* the output */ 
		printf("<sniffjoke service>: %s", received_buf);
	
	close(sock);
}

void check_call_ret(const char *umsg, int objerrno, int ret, bool fatal) 
{
	char errbuf[MSGBUF];

	internal_log(NULL, DEBUG_LEVEL, "checking errno %d message of [%s], return value: %d fatal %d", objerrno, umsg, ret, fatal);

	if (ret != -1)
		return;

	if (objerrno)
		snprintf(errbuf, MSGBUF, "%s: %s", umsg, strerror(objerrno));
	else
		snprintf(errbuf, MSGBUF, "%s ", umsg);

	if (fatal) {
		internal_log(NULL, ALL_LEVEL, "fatal error: %s", errbuf);
		raise(SIGTERM);
	} else {
		internal_log(NULL, ALL_LEVEL, "error: %s", errbuf);
	}
}

/* forceflow is almost useless, use NULL in the normal logging options */
void internal_log(FILE *forceflow, unsigned int errorlevel, const char *msg, ...) 
{
	va_list arguments;
	time_t now = time(NULL);
	FILE *output_flow;
	unsigned int loglevel;

	if (forceflow == NULL && useropt.logstream == NULL)
		return;

	if (forceflow != NULL)
		output_flow = forceflow;
	else
		output_flow = useropt.logstream;

	if (errorlevel == PACKETS_DEBUG && useropt.packet_logstream != NULL)
		output_flow = useropt.packet_logstream;

	if (errorlevel == SESSION_DEBUG && useropt.session_logstream != NULL)
		output_flow = useropt.session_logstream;

	/* is checked sjconf->running->debug_level instead of useropt.debug_level
	 * because the user should chage it with the "set" command */
	if(sjconf != NULL)
		loglevel = sjconf->running.debug_level;
	else
		loglevel = useropt.debug_level;

	if (errorlevel <= loglevel) { 
		char *time = strdup(asctime(localtime(&now)));

		va_start(arguments, msg);
		time[strlen(time) -1] = ' ';
		fprintf(output_flow, "%s ", time);
		vfprintf(output_flow, msg, arguments);
		fprintf(output_flow, "\n");
		fflush(output_flow);
		va_end(arguments);
		free(time);
	}
}

void* memset_random(void *s, size_t n)
{
	char *cp = (char*)s;
	while (n-- > 0)
		*cp++ = (char)random();
	return s;
}

int main(int argc, char **argv)
{
	bool restart_on_restore = false;
	char command_buffer[MEDIUMBUF], *command_input = NULL;
	int charopt, listening_unix_socket;
	pid_t previous_pid;
	
	/* set the default values in the configuration struct */
	useropt.cfgfname = CONF_FILE;
	useropt.user = DROP_USER;
	useropt.group = DROP_GROUP;
	useropt.chroot_dir = CHROOT_DIR;
	useropt.logfname = LOGFILE;
	useropt.debug_level = DEFAULT_DEBUG_LEVEL;
	useropt.enabler = PLUGINSENABLER;

	useropt.go_foreground = false;
	useropt.force_restart = false;
	useropt.logstream = stdout;
	useropt.packet_logstream = stdout;
	useropt.session_logstream = stdout;
	
	struct option sj_option[] =
	{
		{ "config", required_argument, NULL, 'f' },
		{ "user", required_argument, NULL, 'u' },
		{ "group", required_argument, NULL, 'g' },
		{ "chroot-dir", required_argument, NULL, 'c' },
		{ "debug", required_argument, NULL, 'd' },
		{ "logfile", required_argument, NULL, 'l' },
		{ "enabler", required_argument, NULL, 'e' },
		{ "foreground", no_argument, NULL, 'x' },
		{ "force", no_argument, NULL, 'r' },
		{ "help", no_argument, NULL, 'h' },
		{ "version", no_argument, NULL, 'v' },
		{ NULL, 0, NULL, 0 }
	};

	memset(command_buffer, 0x00, MEDIUMBUF);
	/* check for direct commands */
	if ((argc >= 2) && !memcmp(argv[1], "start", strlen("start"))) {
		snprintf(command_buffer, MEDIUMBUF, "start");
		command_input = argv[1];
	}
	if ((argc >= 2) && !memcmp(argv[1], "stop", strlen("stop"))) {
		snprintf(command_buffer, MEDIUMBUF, "stop");
		command_input = argv[1];
	}
	if ((argc >= 2) && !memcmp(argv[1], "stat", strlen("stat"))) {
		snprintf(command_buffer, MEDIUMBUF, "stat");
		command_input = argv[1];
	}
	if ((argc == 5) && !memcmp(argv[1], "set", strlen("set"))) {
		snprintf(command_buffer, MEDIUMBUF, "set %s %s %s", argv[2], argv[3], argv[4]);
		command_input = command_buffer;
	} 
	if ((argc == 2) && !memcmp(argv[1], "clear", strlen("clear"))) {
		snprintf(command_buffer, MEDIUMBUF, "clear");
		command_input = command_buffer;
	} 
	if ((argc == 2) && !memcmp(argv[1], "showport", strlen("showport"))) {
		snprintf(command_buffer, MEDIUMBUF, "showport");
		command_input = command_buffer;
	} 
	if ((argc == 2) && !memcmp(argv[1], "quit", strlen("quit"))) {
		snprintf(command_buffer, MEDIUMBUF, "quit");
		command_input = command_buffer;
	}
	if ((argc == 2) && !memcmp(argv[1], "info", strlen("info"))) {
		snprintf(command_buffer, MEDIUMBUF, "info");
		command_input = command_buffer;
	}
	if ((argc == 3) && !memcmp(argv[1], "loglevel", strlen("loglevel"))) {
		snprintf(command_buffer, MEDIUMBUF, "loglevel %s", argv[2]);
		command_input = command_buffer;
	}

	if (command_input == NULL) {
		while ((charopt = getopt_long(argc, argv, "f:u:g:c:d:l:e:xrhv", sj_option, NULL)) != -1) {
			switch(charopt) {
				case 'f':
					useropt.cfgfname = strdup(optarg);
					break;
				case 'u':
					useropt.user = strdup(optarg);
					break;
				case 'g':
					useropt.group = strdup(optarg);
					break;
				case 'c':
					useropt.chroot_dir = strdup(optarg);
					break;
				case 'l':
					useropt.logfname = strdup(optarg);
					break;
				case 'd':
					useropt.debug_level = atoi(optarg);
					break;
				case 'x':
					useropt.go_foreground = true;
					break;
				case 'r':
					useropt.force_restart = true;
					break;
				case 'v':
					sj_version(argv[0]);
					return 0;
				case 'e':
					useropt.enabler = strdup(optarg);
					break;
				default:
					sj_help(argv[0], useropt.chroot_dir);
					return -1;

				argc -= optind;
				argv += optind;
			}
		}
	
	}

	SjProc = new Process(&useropt);
	if (SjProc->failure) {
		sj_help(argv[0], useropt.chroot_dir);
		delete SjProc;
		return 0;
	}


	/* client-like usage: if a command line is present, send the command to the running sniffjoke service */
	if (command_input != NULL) 
	{
		pid_t service_pid = SjProc->readPidfile();

		if (!service_pid) {
			internal_log(NULL, ALL_LEVEL, "warning: sniffjoke is not running, command %s ignored", command_input);
			return 0;
		}
	
		/* configuration is required for the client, too, for this reason a service started with a non-default
		 * chroot need to be used as argument in the client too. */	
		sjconf = new UserConf(&useropt);

		/* if a user and a group ar not specified, defaults are used */
		SjProc->Jail(useropt.chroot_dir, &sjconf->running);
		if (SjProc->failure == true) {
			internal_log(NULL, ALL_LEVEL, "error in process handling, closing");
			delete SjProc;
		}

		SjProc->PrivilegesDowngrade(&sjconf->running);

		client_send_command(command_input);

		/* sniffjoke in client mode don't require any specific cleaning */
		return 0;
	}
	
	if (argc > 1 && argv[1][0] != '-') {
		internal_log(stderr, ALL_LEVEL, "wrong usage of sniffjoke: beside commands, only --long-opt are accepted");
		sj_help(argv[0], useropt.chroot_dir);
		return -1;
	}

	if ((previous_pid = SjProc->readPidfile()) != 0)
	{
		if (previous_pid && !useropt.force_restart) {
			internal_log(stderr, ALL_LEVEL, "sniffjoke is already running, use --force or check --help");
			internal_log(stderr, ALL_LEVEL, "the pidfile %s contains the apparently running pid: %d", SJ_PIDFILE, previous_pid);
			return 0;
		}

		internal_log(NULL, VERBOSE_LEVEL, "forcing exit of previous running service %d ...", previous_pid);
		ForcePreviousQuit(previous_pid); 
		internal_log(NULL, ALL_LEVEL, "A new instance of sniffjoke is going running in background");
		/* required because the previous sniffjoke must cleanup the routing ambaradam, fifty thousand millisecs */
		usleep(50000);
		/* for two times, because sometime I get the race condition of an unfound gateway */
		usleep(50000);
	} 

	/* the configuration of sniffjoke for the service instance is readed after the possibile killing of 
	 * the previous instance. */	
	sjconf = new UserConf(&useropt);

	/* running the network setup before the background, for keep the software output visible on the console */
	sjconf->network_setup();

	/* loading the plugins used for tcp hacking */
	conntrack = new TCPTrack(sjconf);
	if(conntrack->fail == true) {
		internal_log(NULL, ALL_LEVEL, "fatal error in initialization hacks plugin, aborted");
		return 0;
	}

	if (!useropt.go_foreground) 
	{
		SjProc->SjBackground();
		SjProc->processIsolation();

		if (SjProc->failure) 
			delete SjProc;
	}
	else {
		useropt.logstream = stdout;
		internal_log(NULL, ALL_LEVEL, "foreground running: logging set on standard output, block with ^c");
	}

	/* setting ^C, SIGTERM and other signal trapped for clean network environment */
	SjProc->sigtrapSetup(sj_sigtrap);

	/* the code flow reach here, SniffJoke is ready to instance network environment */
	mitm = new NetIO(sjconf);

	if (mitm->is_network_down())
	{
		internal_log(stderr, ALL_LEVEL, "detected network error in NetIO constructor: unable to start sniffjoke");
		return 0;
	}

	/* processDetatch, with root permission open the pidfile and in user perm write the child's pid */
	SjProc->processDetach();

	/* Jail chroot + privileges downgrade */	
	SjProc->Jail(useropt.chroot_dir, &sjconf->running);

	/* background running, with different loglevel. logfile opened below: */
	if (!useropt.go_foreground) {	
		if ((useropt.logstream = fopen(useropt.logfname, "a+")) == NULL) {
			internal_log(stderr, ALL_LEVEL, "FATAL ERROR: unable to open %s: %s", useropt.logfname, strerror(errno));
			raise(SIGTERM);
		}
		else
			internal_log(stderr, DEBUG_LEVEL, "opened log file %s", useropt.logfname);
			
		if (useropt.debug_level >= PACKETS_DEBUG) {
			char *tmpfname = (char *)calloc(1, strlen(useropt.logfname) + 10);
			sprintf(tmpfname, "%s.packets", useropt.logfname);
			if ((useropt.packet_logstream = fopen(tmpfname, "a+")) == NULL) {
				internal_log(stderr, ALL_LEVEL, "FATAL ERROR: unable to open %s: %s", tmpfname, strerror(errno));
				raise(SIGTERM);
			} 
			internal_log(NULL, ALL_LEVEL, "opened for packets debug: %s successful", tmpfname);
		}

		if (useropt.debug_level >= SESSION_DEBUG) {
			char *tmpfname = (char *)calloc(1, strlen(useropt.logfname) + 10);
			sprintf(tmpfname, "%s.session", useropt.logfname);
			if ((useropt.session_logstream = fopen(tmpfname, "a+")) == NULL) {
				internal_log(stderr, ALL_LEVEL, "FATAL ERROR: unable to open %s: %s", tmpfname, strerror(errno));
				raise(SIGTERM);
			}
			internal_log(NULL, ALL_LEVEL, "opened for hacks debug: %s successful", tmpfname);
		}
	}

	SjProc->PrivilegesDowngrade(&sjconf->running);

	listening_unix_socket = sj_bind_unixsocket();

	if (sjconf->running.sj_run == false)
		internal_log(NULL, ALL_LEVEL, "sniffjoke is running and INACTIVE: use \"sniffjoke start\" command to start it");

	mitm->prepare_conntrack(conntrack);

	/* main block */
	while (1) {
		SjProc->sigtrapDisable();
		mitm->network_io();
		mitm->queue_flush();

		if (mitm->is_network_down()) {
			if (sjconf->running.sj_run == true) {
				internal_log(NULL, ALL_LEVEL, "Network is down, interrupting sniffjoke");
				sjconf->running.sj_run = false;
				restart_on_restore = true;
			}
		} else {
			if (restart_on_restore == true) {
				internal_log(NULL, ALL_LEVEL, "Network restored, restarting sniffjoke");
				sjconf->running.sj_run = true;
				restart_on_restore = false;
			}
		}
		
		read_unixsock(listening_unix_socket, sjconf);
		SjProc->sigtrapEnable();

	}
	/* nevah here */
}
