#include <iostream>
#include <cerrno>
using namespace std;
#include <string.h>
#include <unistd.h>
#include <signal.h>
#include <stdlib.h>
#include <getopt.h>

#include <netinet/in.h>

#include <sys/types.h>
#include <sys/time.h>
#include <sys/poll.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/un.h>

#include "sniffjoke.h"

const char *default_cfg = "/etc/sniffjoke.conf";
const char *default_log = "/tmp/sniffjoke.log";
const int default_web_bind_port = 8844;


const char *prog_name = "SniffJoke, http://www.delirandom.net/sniffjoke";
const char *help_url = "http://www.delirandom.net/sniffjoke";
const char *prog_version = "0.3";

/* Sniffjoke networking and feature configuration */
static SjConf *sjconf;
/* Sniffjoke man in the middle class and functions */
static NetIO *mitm;
/* WebIO, not required but usefull, implemented with libswill libraries */
static WebIO *webio;
/* connection tracking class and functions */
static TCPTrack *conntrack;
/* process configuration, data struct defined in sniffjoke.h */
static struct sj_useropt useropt;

static void sniffjoke_help(const char *pname) {
	printf(
		"%s receive some --options:\n"
		"--debug [level 1-3]\tenable debug and set the verbosity [default:1]\n"
		"--logfile [file]\tset a logfile, [default %s]\n"
		"--cmd\t\t\tsend a cmd to the running sniffjoke, commands available:\n"
		"\tstart|stop|stat|portrange startport:endport paranoy <1-100>|clear startport:endport\n"
		"--bind-port [port]\tset the port where bind management webserver [default:%d]\n"
		"--bind-addr [addr]\tset interface where bind management webserver [default:%s]\n"
		"--conf [file]\t\tconfiguration file [default:%s]\n"
		"--force\t\t\tforce restart if sniffjoke service\n"
		"--foreground\t\trunning in foreground\n"
		"--version\t\tshow sniffjoke version\n"
		"--help\t\t\tshow this help\n"
		"\t\t\thttp://www.delirandom.net/sniffjoke\n",
	pname, default_log, default_web_bind_port, "127.0.0.1", default_cfg);
}

static void sniffjoke_version(const char *pname) {
	printf("%s %s\n", prog_name, prog_version);
}

/* used in clean closing */
static void clean_pidfile(void) {

	if(access(PIDFILE, R_OK)) {
		FILE *oldpidf = fopen(PIDFILE, "r");
		char oldpid[6];

                fgets(oldpid, 6, oldpidf);
                fclose(oldpidf);

		internal_log(NULL, ALL_LEVEL, "old pidfile %s had pid %d inside, sending sigterm...", PIDFILE, atoi(oldpid));
		kill(atoi(oldpid), SIGTERM);
		/* usleep read microseconds, I need three milliseconds for permit a good cleaning of previous instance */
		usleep(1000 * 3);
	} else {
		internal_log(NULL, ALL_LEVEL, "unable to read %s file, request for unlinking from process %d", PIDFILE, getpid());
	}

	if(unlink(PIDFILE)) {
		internal_log(NULL, DEBUG_LEVEL, "unlinked %s as requested", PIDFILE);
	} else {
		internal_log(NULL, ALL_LEVEL, "unable to unlink %s: %s", PIDFILE, strerror(errno));
		/* and ... ? */
	}
}

void check_call_ret(const char *umsg, int objerrno, int ret, bool fatal) 
{
	char errbuf[STRERRLEN];
	int my_ret = 0;

	internal_log(NULL, DEBUG_LEVEL, "checking errno %d message of [%s], return value: %d fatal %d", objerrno, umsg, ret, fatal);

	if(ret != -1) 
		return;

	if(objerrno)
		snprintf(errbuf, STRERRLEN, "%s: %s", umsg, strerror(objerrno));
	else
		snprintf(errbuf, STRERRLEN, "%s ", umsg);

	if(fatal) {
		internal_log(NULL, ALL_LEVEL, "fatal error: %s", errbuf);
		clean_pidfile();
		exit(1);
	} else {
		internal_log(NULL, ALL_LEVEL, "error: %s", errbuf);
	}
}

void sniffjoke_sigtrap(int signal) 
{
	internal_log(NULL, ALL_LEVEL, "received signal %d, cleaning sniffjoke objects...", signal);

	if(sjconf != NULL) 
		delete sjconf;

	if(webio != NULL) 
		delete webio;

	if(mitm != NULL)
		delete mitm;

	if(conntrack != NULL)
		delete conntrack;

	raise(SIGKILL);
}

/* forceflow is almost useless, use NULL in the normal logging options */
void internal_log(FILE *forceflow, int errorlevel, const char *msg, ...)
{
        va_list arguments;
        time_t now = time(NULL);
        FILE *output_flow;

	if(useropt.logstream == NULL)
		forceflow = stderr;

        if(forceflow != NULL)
                output_flow = forceflow;
        else
                output_flow = useropt.logstream;

        va_start(arguments, msg);

        if(errorlevel <= useropt.debug_level)
        {
                char *time = strdup(asctime(localtime(&now)));

                time[strlen(time) -1] = ' ';
                fprintf(output_flow, "%s ", time);
                vfprintf(output_flow, msg, arguments);
                fprintf(output_flow, "\n");
                fflush(output_flow);

                free(time);
        }

        va_end(arguments);
}

static int sniffjoke_background(void) 
{
	const char *sniffjoke_socket_path ="/tmp/sniffjoke_srv";
	struct sockaddr_un sjsrv;
	int sock;

	if ((sock = socket(AF_UNIX, SOCK_DGRAM, 0)) < 0) {
		internal_log(stdout, ALL_LEVEL, "FATAL ERROR: unable to open unix socket: %s", strerror(errno));
		exit(1);
	}

	memset(&sjsrv, 0x00, sizeof(sjsrv));
	sjsrv.sun_family = AF_UNIX;
	memcpy(sjsrv.sun_path, sniffjoke_socket_path, strlen(sniffjoke_socket_path));

	if (bind(sock, (struct sockaddr *)&sjsrv, sizeof(sjsrv)) < 0) {
		close(sock);
		internal_log(stdout, ALL_LEVEL, "FATAL ERROR: unable to bind unix socket %s: %s", 
			sniffjoke_socket_path, strerror(errno)
		);
		exit(1);
	}        

	internal_log(stdout, VERBOSE_LEVEL, "opened unix socket %s", sniffjoke_socket_path);

	if(useropt.go_foreground) {
		useropt.logstream = stdout;
                internal_log(NULL, ALL_LEVEL, "foreground running: logging set on standard output, block with ^c");
        }
        else {
		if(fork())
			exit(0);

                if((useropt.logstream = fopen(useropt.logfname, "a+")) == NULL) {
                        internal_log(stdout, ALL_LEVEL, "FATAL ERROR: unable to open %s: %s", useropt.logfname, strerror(errno));
                        exit(errno);
                }
                internal_log(NULL, ALL_LEVEL, "new running instance of packet duplicator with pid: %d", getpid());

                FILE *pidfile =fopen(PIDFILE, "w+");
                if(pidfile == NULL) {
                        internal_log(NULL, ALL_LEVEL, "FATAL ERROR: unable to write %s: %s", PIDFILE, strerror(errno));
                        exit(errno);
                } else {
                        fprintf(pidfile, "%d", getpid());
                        fclose(pidfile);
                }
        }
	return sock;
}
        
static pid_t sniffjoke_is_running(void)
{
        FILE *pidf = fopen(PIDFILE, "r");

        if(pidf != NULL) {
                char tmpstr[6];

                fgets(tmpstr, 6, pidf);
                fclose(pidf);

                return atoi(tmpstr);
        }
	else
		return 0;
}


static void send_command(char *cmdstring) {
	printf("todo: inviare il comando %s\n", cmdstring);
}

int main(int argc, char **argv) {
	struct pollfd fds[2];
	int i, nfds, charopt;
	int timeout;
	time_t next_web_poll;
	bool refresh_confile = false;

	/* set the default vaule in the configuration struct */
	useropt.force_restart = false;
	useropt.go_foreground = false;
 	useropt.debug_level = 0;
	useropt.logfname = "/tmp/sniffjoke_tmp.log";
	useropt.cfgfname = "/etc/sniffjoke.conf";
	useropt.bind_port = default_web_bind_port;
	useropt.bind_addr = NULL;
	useropt.command_input = NULL;   

	struct option sj_option[] =
	{
		{ "debug", required_argument, NULL, 'd' },
		{ "cmd", required_argument, NULL, 'c' },
		{ "bind-port", required_argument, NULL, 'p' },
		{ "bind-addr", required_argument, NULL, 'a' },
		{ "help", optional_argument, NULL, 'h' },
		{ "logfile", required_argument, NULL, 'l' },
		{ "conf", required_argument, NULL, 'f' },
		{ "force", optional_argument, NULL, 'r' },
		{ "version", optional_argument, NULL, 'v' },
		{ NULL, 0, NULL, 0 }
	};

	for(i = 1; i < argc; i++) {
		if(argv[i][0] == '-' && argv[i][1] != '-') {
			internal_log(stdout, ALL_LEVEL, "options: %s wrong: only --long-options are accepted", argv[i]);
			sniffjoke_help(argv[0]);
			return -1;
		}
	}

	while((charopt = getopt_long(argc, argv, "dcpahlfvr", sj_option, NULL)) != -1)
	{
		switch(charopt) {
			case 'd':
				useropt.debug_level = atoi(optarg);
				break;
			case 'c':
				useropt.command_input = strdup(optarg);
				break;
			case 'p':
				useropt.bind_port = atoi(optarg);
				break;
			case 'a':
				useropt.bind_addr = strdup(optarg);
				break;
			case 'h':
				sniffjoke_help(argv[0]);
				return -1;
			case 'l':
				useropt.logfname = strdup(optarg);
				break;
			case 'f':
				useropt.cfgfname = strdup(optarg);
				break;
			case 'v':
				sniffjoke_version(argv[0]);
				return 0;
			case 'r':
				useropt.force_restart = true;
				break;
			default:
				sniffjoke_help(argv[0]);
				return -1;

			argc -= optind;
			argv += optind;
		}
	}

	/* check integrity of the readed options */
	/* bind port is ok: start set to default, is unsigned short, if overwritte in fine */

	/* checking config file */
	if(useropt.cfgfname != NULL && access(useropt.cfgfname, W_OK)) {
		internal_log(stdout, ALL_LEVEL, "unable to access %s, running default conf and autodetect if not available", 
			useropt.cfgfname
		);
		check_call_ret("invalid --config file", errno, -1, false);
	}
	else
		useropt.cfgfname = (char *)default_cfg;

	/* bind addr */
	if(useropt.bind_addr != NULL) {
		// FIXME
		internal_log(stdout, ALL_LEVEL, "warning: --bind-addr is IGNORED at the moment: %s\n", useropt.bind_addr);
	}

	/* check if sniffjoke is running in background */
	/* check cmd option */
	pid_t sniffjoke_srv = sniffjoke_is_running();

	if(sniffjoke_srv) {
		internal_log(stdout, ALL_LEVEL, "sniffjoke is already running in background: pid %d", sniffjoke_srv);
	}

	if(useropt.command_input != NULL) 
	{
		pid_t sniffjoke_srv = sniffjoke_is_running();

		if(sniffjoke_srv) 
		{
			internal_log(stdout, ALL_LEVEL, "sending command: [%s] to sniffjoke service", useropt.command_input);

			send_command(useropt.command_input);
			exit(1);
		}
		else {
			internal_log(stdout, ALL_LEVEL, "warning: sniffjoke is not running, --cmd %s ignored",
				useropt.command_input);
			/* the running proceeding */
		}

	} else {
		if(sniffjoke_srv && !useropt.force_restart) {
			internal_log(stdout, ALL_LEVEL, "sniffjoke is running and force restart is not request, quitting");
			exit(1);
		}
	}

	if(useropt.force_restart)
		clean_pidfile();

	if(getuid() || geteuid()) 
		check_call_ret("required root privileges", EPERM, -1, true);

	/* after the privilege checking */
	if(sniffjoke_srv && useropt.force_restart)

	/* setting ^C, SIGTERM and other signal trapped for clean network environment */
	signal(SIGINT, sniffjoke_sigtrap);
	signal(SIGABRT, sniffjoke_sigtrap);
	signal(SIGTERM, sniffjoke_sigtrap);
	signal(SIGQUIT, sniffjoke_sigtrap);

	sjconf = new SjConf( &useropt );
	webio = new WebIO( sjconf );

	if(sjconf->running->sj_run == 0) {
		internal_log(NULL, ALL_LEVEL,
			"sniffjoke is not running: use \"sniffjoke --cmd start\" or http://127.0.0.1:%d/sniffjoke.html\n",
                        sjconf->running->web_bind_port
		);
	}
	/* setting logfile, debug level, background running and unix socket */
	sniffjoke_background();

	/* this jump happen when sniffjoke is stopped */
restart:
	/* loop until sj_run is TRUE */
	while(sjconf->running->sj_run == 0) 
	{
		refresh_confile = true;
		webio->web_poll();
		usleep(50000);
	}

	/* if code flow reach here, SniffJoke is running */
	mitm = new NetIO( sjconf );

	if(mitm->networkdown_condition)
	{
		internal_log(NULL, ALL_LEVEL, "Fatal error in NetIO constructor: stopping sniffjoke");
		sjconf->running->sj_run = 0;
		delete mitm;
		goto restart;
	}

	/* this variable is used in the main loop, for raise the new configuration */
	sjconf->running->reload_conf = false;

	conntrack = new TCPTrack( sjconf );

	/* we update the config file only if explicitally requested */
	if(refresh_confile && useropt.cfgfname != NULL) {
		sjconf->dump_config( useropt.cfgfname );
	}
	else if(useropt.cfgfname == NULL) {
		internal_log(NULL, ALL_LEVEL, "configuration file is not set as argument, sniffjoke not overwrite the default %s", default_cfg);
	}
	else {
		internal_log(NULL, ALL_LEVEL, "configuration unchanged");
	}

	/* Open STREAMS device. */
	fds[0].fd = mitm->tunfd;
	fds[1].fd = mitm->netfd;
	fds[0].events = POLLIN | POLLPRI;
	fds[1].events = POLLIN | POLLPRI;

	/* epoll_wait wants milliseconds, I want 0.2 sec of delay */
	timeout = (1000 * 1000 / 5); // WARNING - poll = microsecond, epoll = milliseconds

	next_web_poll = time(NULL) + 1;

	/* main block */
	while(1) 
	{
		nfds = poll(fds, 2, timeout);

		switch(nfds) 
		{
		case -1:
			check_call_ret("error in poll", errno, nfds, true);
			return -1;
		case 0:
			if(sjconf->running->reload_conf) {
				internal_log(NULL, ALL_LEVEL, "requested configuration reloading, restarting sniffjoke");
				refresh_confile = true;

				delete mitm;
				delete conntrack;
				goto restart;
			}
			if(mitm->networkdown_condition) {
				internal_log(NULL, ALL_LEVEL, "Network is down, interrumpting sniffjoke");

				delete mitm;
				delete conntrack;
				goto restart;
			}
			break;
		default:
			/* 
			 * this because, if I've always network I/O, timeout never 
			 * expire and web_poll is not called.
			 */
			for(int i = 0; i < 2; i++) 
			{
				if (fds[i].fd == mitm->tunfd && fds[i].revents & (POLLIN | POLLPRI))
					mitm->network_io( TUNNEL, conntrack );
				else if ((fds[i].fd == mitm->netfd) && fds[i].revents & (POLLIN | POLLPRI))
					mitm->network_io( NETWORK, conntrack );
			}

			conntrack->analyze_packets_queue();
			mitm->queue_flush( conntrack );
		}

		if(time(NULL) >= next_web_poll) {
			webio->web_poll();
			next_web_poll = time(NULL) + 1;
		}
	}
	/* nevah here */
}
