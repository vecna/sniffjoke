#include <iostream>
#include <cerrno>
using namespace std;
#include <string.h>
#include <unistd.h>
#include <signal.h>
#include <stdlib.h>
#include <getopt.h>
#include <fcntl.h>

#include <netinet/in.h>

#include <sys/types.h>
#include <sys/time.h>
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

static void sniffjoke_sigtrap(int signal) 
{
	if(signal)
		internal_log(NULL, ALL_LEVEL, "received signal %d, cleaning sniffjoke objects...", signal);
	/* else, is the clean way used for sniffjoke to clean object */

	if(sjconf != NULL) 
		delete sjconf;

	if(webio != NULL) 
		delete webio;

	if(mitm != NULL)
		delete mitm;

	raise(SIGKILL);
}

/* used in clean closing */
static void clean_pidfile_exit(bool exit_request) {

	if(!access(PIDFILE, R_OK)) {
		FILE *oldpidf = fopen(PIDFILE, "r");
		char oldpid[6];

		if(oldpidf == NULL) {
			internal_log(NULL, ALL_LEVEL, "unable to open %s: %s", PIDFILE, strerror(errno));
			return;
		}

                fgets(oldpid, 6, oldpidf);
                fclose(oldpidf);

		internal_log(NULL, VERBOSE_LEVEL, "old pidfile %s had pid %d inside, sending sigterm...", PIDFILE, atoi(oldpid));
		kill(atoi(oldpid), SIGTERM);
		/* usleep read microseconds, I need three milliseconds for permit a good cleaning of previous instance */
		usleep(1000 * 3);
	} else {
		internal_log(NULL, ALL_LEVEL, "unable to access %s file, request for unlinking from process %d: %s", PIDFILE, getpid(), strerror(errno));
	}

	if(!unlink(PIDFILE)) {
		internal_log(NULL, DEBUG_LEVEL, "unlinked %s as requested", PIDFILE);
	} else {
		internal_log(NULL, ALL_LEVEL, "unable to unlink %s: %s", PIDFILE, strerror(errno));
		/* and ... ? */
	}

	/* this is the clean way for exit, because sniffjoke_sigtrap delete the instance c++ obj */
	if(exit_request)
		sniffjoke_sigtrap(0);
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
		clean_pidfile_exit(true);
	} else {
		internal_log(NULL, ALL_LEVEL, "error: %s", errbuf);
	}
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

	if(errorlevel == PACKETS_DEBUG && useropt.packet_logstream != NULL)
		output_flow = useropt.packet_logstream;

	if(errorlevel == HACKS_DEBUG && useropt.hacks_logstream != NULL)
		output_flow = useropt.hacks_logstream;

        if(errorlevel <= useropt.debug_level)
        {
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

static int sniffjoke_background(void) 
{
	const char *sniffjoke_socket_path = SNIFFJOKE_SRV_US;
	struct sockaddr_un sjsrv;
	int sock;

	if ((sock = socket(AF_UNIX, SOCK_DGRAM, 0)) == -1) {
		internal_log(stdout, ALL_LEVEL, "fatal: unable to open unix socket: %s", strerror(errno));
		clean_pidfile_exit(true);
	}

	memset(&sjsrv, 0x00, sizeof(sjsrv));
	sjsrv.sun_family = AF_UNIX;
	memcpy(sjsrv.sun_path, sniffjoke_socket_path, strlen(sniffjoke_socket_path));

	if(!access(sniffjoke_socket_path, F_OK))
		if(unlink(sniffjoke_socket_path)) {
			internal_log(stdout, ALL_LEVEL, "fatal: unable to unlink previous instance of %s: %s", 
				sniffjoke_socket_path, strerror(errno));
			clean_pidfile_exit(true);
		}
			

	if (bind(sock, (struct sockaddr *)&sjsrv, sizeof(sjsrv)) == -1) {
		close(sock);
		internal_log(stdout, ALL_LEVEL, "fatal: unable to bind unix socket %s: %s", 
			sniffjoke_socket_path, strerror(errno)
		);
		clean_pidfile_exit(true);
	}

	if(fcntl(sock, F_SETFL, O_NONBLOCK) == -1) {
		close(sock);
		internal_log(stdout, ALL_LEVEL, "fatal: unable to set non blocking unix socket %s: %s",
			sniffjoke_socket_path, strerror(errno)
		);
		clean_pidfile_exit(true);
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
			clean_pidfile_exit(true);
		}

		if(useropt.debug_level >= PACKETS_DEBUG) {
			char *tmpfname = (char *)malloc(strlen(useropt.logfname) + 10);
			sprintf(tmpfname, "%s.packets", useropt.logfname);
			if((useropt.packet_logstream = fopen(tmpfname, "a+")) == NULL) {
				internal_log(stdout, ALL_LEVEL, "FATAL ERROR: unable to open %s: %s", tmpfname, strerror(errno));
				clean_pidfile_exit(true);
			} 
			internal_log(stdout, ALL_LEVEL, "opened for packets debug: %s successful", tmpfname);
		}

		if(useropt.debug_level >= HACKS_DEBUG) {
			char *tmpfname = (char *)malloc(strlen(useropt.logfname) + 10);
			sprintf(tmpfname, "%s.hacks", useropt.logfname);
			if((useropt.hacks_logstream = fopen(tmpfname, "a+")) == NULL) {
				internal_log(stdout, ALL_LEVEL, "FATAL ERROR: unable to open %s: %s", tmpfname, strerror(errno));
				clean_pidfile_exit(true);
			}
			internal_log(stdout, ALL_LEVEL, "opened for hacks debug: %s successful", tmpfname);
		}

                FILE *pidfile =fopen(PIDFILE, "w+");
                if(pidfile == NULL) {
                        internal_log(NULL, ALL_LEVEL, "FATAL ERROR: unable to write %s: %s", PIDFILE, strerror(errno));
			clean_pidfile_exit(true);
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
	pid_t potenctial_pid;
	int killret;

        if(pidf != NULL) {
                char tmpstr[6];

                fgets(tmpstr, 6, pidf);
                fclose(pidf);

		potenctial_pid = atoi(tmpstr);
        }
	else
		return 0;

	/* test if the pid is running again */
	killret = kill(potenctial_pid, SIGUSR1);
	if(!killret)
		return potenctial_pid;
	else {
		if(errno == EPERM) {
			internal_log(NULL, ALL_LEVEL, "you have not privileges to kill previous sniffjoke, running on %d", potenctial_pid);
			exit(0);
		}
		else /* (errno == ESRCH) */ {
			internal_log(NULL, ALL_LEVEL, "the pidfile contains information about a dead process (%d)", potenctial_pid);
			clean_pidfile_exit(false);
			return 0;
		}
	}
}

/* internal routine called in send_command and check_local_unixserv */
static int receive_unix_data(int _sock, char *databuf, int bufsize, struct sockaddr *from, FILE *error_flow, const char *usermsg)
{
	int fromlen =sizeof(struct sockaddr_un), ret;

	if((ret = recvfrom(_sock, databuf, bufsize, 0, from, (socklen_t *)&fromlen)) == -1) 
	{
		if(errno == EAGAIN || errno == EWOULDBLOCK) {
			return 0;
		}

		internal_log(error_flow, ALL_LEVEL, "unable to receive local socket: %s: %s", usermsg, strerror(errno));
	}

	return ret;
}

static void send_command(char *cmdstring) 
{
	int sock;
	char received_buf[HUGEBUF];
	struct sockaddr_un servaddr;/* address of server */
	struct sockaddr_un clntaddr;/* address of client */
	struct sockaddr_un from; /* address used for receiving data */
	int rlen;
       
        /* Create a UNIX datagram socket for client */
	if ((sock = socket(AF_UNIX, SOCK_DGRAM, 0)) == -1) {
		internal_log(stdout, ALL_LEVEL, "unable to open UNIX socket for connect to sniffjoke server: %s", strerror(errno));
		exit(0);
	}
        
	unlink(SNIFFJOKE_CLI_US);
	/* Client will bind to an address so the server will get an address in its recvfrom call and use it to
	 * send data back to the client.  
	 */
	memset(&clntaddr, 0x00, sizeof(clntaddr));
	clntaddr.sun_family = AF_UNIX;
	strcpy(clntaddr.sun_path, SNIFFJOKE_CLI_US);

	if (bind(sock, (const sockaddr *)&clntaddr, sizeof(clntaddr)) == -1) {
		internal_log(stdout, ALL_LEVEL, "unable to bind client to %s: %s", SNIFFJOKE_CLI_US, strerror(errno));
		exit(0);
	}
       
        /* Set up address structure for server socket */
	memset(&servaddr, 0x00, sizeof(servaddr));
	servaddr.sun_family = AF_UNIX;
	strcpy(servaddr.sun_path, SNIFFJOKE_SRV_US);

	if(sendto(sock, cmdstring, strlen(cmdstring), 0, (const struct sockaddr *)&servaddr, sizeof(servaddr)) == -1) {
		internal_log(stdout, ALL_LEVEL, "unable to send message [%s]: %s", cmdstring, strerror(errno));
		exit(0);
	}

	if((rlen =receive_unix_data(sock, received_buf, HUGEBUF, (struct sockaddr *)&from, stdout, "from the command sending engine")) == -1) 
		exit(0); // the error message has been delivered 

	if(rlen == 0)
		internal_log(stdout, ALL_LEVEL, "unreceived responde from command [%s]", cmdstring);
	else	/* the output */
		printf("%s", received_buf);
	
        unlink(SNIFFJOKE_CLI_US);
        close(sock);
}

/* function used in sostitution/or with, the web interface, in order to receive command and modify
 * the running conf, display stats and so on 
 */
static void check_local_unixserv(int srvsock, SjConf *confobj)
{
	char received_command[MEDIUMBUF], *output =NULL;
	int i, rlen, cmdlen;
	struct sockaddr_un fromaddr;

	memset(received_command, 0x00, MEDIUMBUF);
	if((rlen =receive_unix_data(srvsock, received_command, MEDIUMBUF, (struct sockaddr *)&fromaddr, NULL, "from the command receiving engine")) == -1) 
		clean_pidfile_exit(true);

	if(!rlen)
		return;

	internal_log(NULL, VERBOSE_LEVEL, "received command from the client: %s", received_command);

	/* FIXME - sanity check del comando ricevuto */
	if(!memcmp(received_command, "stat", strlen("stat") )) {
		output = sjconf->handle_stat_command();
	} else if(!memcmp(received_command, "start", strlen("start") )) {
		output = sjconf->handle_start_command();
	} else if(!memcmp(received_command, "stop", strlen("stop") )) {
		output = sjconf->handle_stop_command();
	} else {
		internal_log(NULL, ALL_LEVEL, "wrong command %s", received_command);
	}

	/* send the answer message to the client */
	if(output != NULL) {
		sendto(srvsock, output, strlen(output), 0, (struct sockaddr *)&fromaddr, sizeof(fromaddr));
	}
}

int main(int argc, char **argv) {
	int i, charopt, local_input = 0;
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
		{ "foreground", optional_argument, NULL, 'x' },
		{ NULL, 0, NULL, 0 }
	};

	for(i = 1; i < argc; i++) {
		if(argv[i][0] == '-' && argv[i][1] != '-') {
			internal_log(stdout, ALL_LEVEL, "options: %s wrong: only --long-options are accepted", argv[i]);
			sniffjoke_help(argv[0]);
			return -1;
		}
	}

	while((charopt = getopt_long(argc, argv, "dcpahlfvrx", sj_option, NULL)) != -1)
	{
		switch(charopt) {
			case 'x':
				useropt.go_foreground = true;
				break;
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

	if(useropt.command_input != NULL) 
	{
		pid_t sniffjoke_srv = sniffjoke_is_running();

		if(sniffjoke_srv) 
		{
			internal_log(stdout, ALL_LEVEL, "sending command: [%s] to sniffjoke service", useropt.command_input);

			send_command(useropt.command_input);
			/* KKK: not clean_pidfile because the other process must continue to run, and not _sigtrap because there
			 * are not obj instanced */
			exit(0);
		}
		else {
			internal_log(stdout, ALL_LEVEL, "warning: sniffjoke is not running, --cmd %s ignored",
				useropt.command_input);
			exit(0); // or:
			/* the running proceeding */
				// ?
		}

	} else {
		if(sniffjoke_srv && !useropt.force_restart) {
			internal_log(stdout, ALL_LEVEL, "sniffjoke is already running (pid %d), use --force or check --help", sniffjoke_srv);
			/* same reason of KKK before */
			exit(0);
		}
	}

	if(getuid() || geteuid()) 
		check_call_ret("required root privileges", EPERM, -1, true);

	/* after the privilege checking */
	if(sniffjoke_srv && useropt.force_restart) {
		kill(sniffjoke_srv, SIGTERM);
		clean_pidfile_exit(false);
		internal_log(stdout, VERBOSE_LEVEL, "sniffjoke remove previous pidfile and killed %d process...", sniffjoke_srv);
	}

	/* setting ^C, SIGTERM and other signal trapped for clean network environment */
	signal(SIGINT, sniffjoke_sigtrap);
	signal(SIGABRT, sniffjoke_sigtrap);
	signal(SIGTERM, sniffjoke_sigtrap);
	signal(SIGQUIT, sniffjoke_sigtrap);
	signal(SIGUSR1, SIG_IGN);

	/* initialiting object configuration and web interface */
	sjconf = new SjConf( &useropt );
	webio = new WebIO( sjconf );

	if(sjconf->running->sj_run == 0) {
		internal_log(NULL, ALL_LEVEL,
			"sniffjoke is not running: use \"sniffjoke --cmd start\" or http://127.0.0.1:%d/sniffjoke.html\n",
                        sjconf->running->web_bind_port
		);
	}
	/* setting logfile, debug level, background running and unix socket */
	if(!useropt.go_foreground)
		local_input = sniffjoke_background();
	else
		internal_log(NULL, ALL_LEVEL, "remind: using foreground running disable the --cmd command sending");

	/* this jump happen when sniffjoke is stopped */
restart:
	/* loop until sj_run is TRUE */
	while(sjconf->running->sj_run == 0) 
	{
		refresh_confile = true;
		webio->web_poll();

		if(!useropt.go_foreground)
			check_local_unixserv(local_input, sjconf);

		usleep(1000 * 50); // usleep receive in input microseconds; 1000 * 50 = 50 millisec */
	}

	/* if code flow reach here, SniffJoke is running */
	mitm = new NetIO( sjconf );

	if(mitm->networkdown_condition)
	{
		internal_log(NULL, ALL_LEVEL, "detected error in NetIO constructor: stopping sniffjoke");
		sjconf->running->sj_run = 0;
		delete mitm;
		mitm = NULL;
		goto restart;
	}

	/* this variable is used in the main loop, for raise the new configuration */
	sjconf->running->reload_conf = false;

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

	next_web_poll = time(NULL) + 1;

	/* main block */
	while(1) 
	{
		if(sjconf->running->reload_conf || mitm->networkdown_condition || sjconf->running->sj_run == false) 
		{
			if(sjconf->running->reload_conf) {
				internal_log(NULL, ALL_LEVEL, "requested configuration reloading, restarting sniffjoke");
				refresh_confile = true;
			} 
			if(mitm->networkdown_condition)
				internal_log(NULL, ALL_LEVEL, "Network is down, interrupting sniffjoke");
			if(sjconf->running->sj_run == false) 
				internal_log(NULL, ALL_LEVEL, "Interrupted sniffjoke as requested");

			delete mitm;
			mitm = NULL;
			goto restart;
		}

		mitm->network_io();
		mitm->queue_flush();

		if(time(NULL) >= next_web_poll) 
		{
			webio->web_poll();

			if(!useropt.go_foreground)
				check_local_unixserv(local_input, sjconf);

			next_web_poll = time(NULL) + 1;
		}
	}
	/* nevah here */
}
