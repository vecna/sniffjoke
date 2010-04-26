#include <iostream>
#include <cerrno>
using namespace std;
#include <string.h>
#include <sys/time.h>
#include <unistd.h>
#include <signal.h>
#include <stdlib.h>
#include <getopt.h>
#include <sys/select.h>
#include <sys/types.h>

#include "sniffjoke.h"

const char *default_cfg = "/etc/sniffjoke.conf";
const char *default_log = "/tmp/sniffjoke.log";
const int default_web_bind_port = 8844;


const char *prog_name = "SniffJoke, http://www.delirandom.net/sniffjoke";
const char *help_url = "http://www.delirandom.net/sniffjoke";
const char *prog_version = "0.3";

static SjConf *sjconf;
static NetIO *mitm;
static WebIO *webio;
static TCPTrack *conntrack;

static void sniffjoke_help(const char *pname) {
	printf(
		"%s receive some --options:\n"
		"--debug [level 1-3]\tenable debug and set the verbosity [default:1]\n"
		"--logfile [file]\tset a logfile, [default %s]\n"
		"--cmd\t\t\tsend a cmd to a running sniffjoke without the web gui\n"
		"--bind-port [port]\tset the port where bind management webserver [default:%d]\n"
		"--bind-addr [addr]\tset interface where bind management webserver [default:%s]\n"
		"--conf [file]\t\tconfiguration file [default:%s]\n"
		"--version\t\tshow sniffjoke version\n"
		"--help\t\t\tshow this help\n"
		"\t\t\thttp://www.delirandom.net/sniffjoke\n",
	pname, default_log, default_web_bind_port, "127.0.0.1", default_cfg);
}

static void sniffjoke_version(const char *pname) {
	printf("%s %s\n", prog_name, prog_version);
}

int check_call_ret(const char *umsg, int objerrno, int ret, char **em, int *el) {

	int my_ret = 0;

	if(ret != -1) {
		return my_ret;
	}

	if(em == NULL) 
	{
		if(objerrno)
			printf("%s: %s (%d)\n", umsg, strerror(objerrno), objerrno);
		else
			printf("%s\n", umsg);

		/* close application in fatal error */
		exit(0);
	}

	/* else, ret == -1 and em != NULL */
	char errbuf[STRERRLEN];
	int len;

	len = snprintf(errbuf, STRERRLEN, "error %d %s:%s\n",
		objerrno, umsg, strerror(objerrno) 
	);
	*em = (char *)calloc(len + 1, sizeof(char) );
	*el = len;

	/* the last byte, the len +1, is set to 0 by calloc */
	memcpy(*em, errbuf, *el);

	return -1;
}

void sniffjoke_sigtrap(int signal) 
{
	printf("\nreceived signal %d, cleaning sniffjoke objects...\n", signal);

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

int main(int argc, char **argv) {
	fd_set infd;
	int i, x, charopt, nfds;
	struct timeval timeout;
	bool refresh_confile = false;

    struct sj_useropt user_opt;
 	user_opt.debug_level = 0;
	user_opt.logfname = NULL;
	user_opt.cfgfname = NULL;
	user_opt.bind_port = default_web_bind_port;
	user_opt.bind_addr = NULL;
	user_opt.command_input = NULL;   

	struct option sj_option[] =
	{
		{ "debug", required_argument, NULL, 'd' },
		{ "cmd", required_argument, NULL, 'c' },
		{ "bind-port", required_argument, NULL, 'p' },
		{ "bind-addr", required_argument, NULL, 'a' },
		{ "help", optional_argument, NULL, 'h' },
		{ "logfile", required_argument, NULL, 'l' },
		{ "conf", required_argument, NULL, 'f' },
		{ "version", optional_argument, NULL, 'v' },
		{ NULL, 0, NULL, 0 }
	};

	for(i = 1; i < argc; i++) {
		if(argv[i][0] == '-' && argv[i][1] != '-') {
			printf("options: %s wrong: only --long-options are accepted\n", argv[i]);
			sniffjoke_help(argv[0]);
			return -1;
		}
	}


	while((charopt = getopt_long(argc, argv, "dcpahlfv", sj_option, NULL)) != -1)
	{
		switch(charopt) {
			case 'd':
			    user_opt.debug_level = atoi(optarg);
				break;
			case 'c':
			    user_opt.command_input = strdup(optarg);
				break;
			case 'p':
				user_opt.bind_port = atoi(optarg);
				break;
			case 'a':
				user_opt.bind_addr = strdup(optarg);
				break;
			case 'h':
				sniffjoke_help(argv[0]);
				return -1;
			case 'l':
				user_opt.logfname = strdup(optarg);
				break;
			case 'f':
				user_opt.cfgfname = strdup(optarg);
				break;
			case 'v':
				sniffjoke_version(argv[0]);
				return 0;
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
	if(user_opt.cfgfname != NULL && access(user_opt.cfgfname, W_OK)) {
		check_call_ret("invalid --config file", errno, -1, NULL, NULL);
	}
	else
		user_opt.cfgfname = (char *)default_cfg;

	/* bind addr */
	if(user_opt.bind_addr != NULL) {
		printf("--bind-addr is IGNORED at the moment: %s\n", user_opt.bind_addr);
		exit(1);
	}

	/* check if sniffjoke is running in background */
	/* check cmd option */
	if(user_opt.command_input != NULL) {
		printf("--cmd is IGNORED at the moment: %s\n", user_opt.command_input);
		exit(1);
	}

	if(getuid() || geteuid()) 
		check_call_ret("required root privileges", EPERM, -1, NULL, NULL);

	/* setting ^C, SIGTERM and other signal trapped for clean network environment */
	signal(SIGINT, sniffjoke_sigtrap);
	signal(SIGABRT, sniffjoke_sigtrap);
	signal(SIGTERM, sniffjoke_sigtrap);
	signal(SIGQUIT, sniffjoke_sigtrap);

	sjconf = new SjConf( &user_opt );
	webio = new WebIO( sjconf );

restart:

	if(sjconf->running->sj_run == 0)
		printf("sniffjoke is NOT running, you could start it with 'SniffJoke Start' in: "
		       "http://127.0.0.1:%d/sniffjoke.html\n",
			sjconf->running->web_bind_port
		);
	else
		printf("sniffjoke is running, you could stop it with 'SniffJoke Stop' in: "
		       "http://127.0.0.1:%d/sniffjoke.html\n",
			sjconf->running->web_bind_port
		);

	/* loop until sj_run is TRUE */
	while(sjconf->running->sj_run == 0) 
	{
		refresh_confile = true;
		webio->web_poll();
		usleep(50000);
	}

	/* if code flow reach here, SniffJoke is running */

	mitm = new NetIO( sjconf );

	if(mitm->error_msg != NULL) 
	{
		sjconf->dump_error(mitm->error_msg, mitm->error_len);
		sjconf->running->sj_run = 0;
		delete mitm;
		goto restart;
	}

	/* this variable is used in the main loop, for raise the new configuration */
	sjconf->running->reload_conf = false;

	conntrack = new TCPTrack( sjconf );

	/* we update the config file only if explicitally requested */
	if(refresh_confile && user_opt.cfgfname != NULL) {
		sjconf->dump_config( user_opt.cfgfname );
	}
	else if(user_opt.cfgfname == NULL) {
		printf("- configuration file is not set as argument\n");
		printf("- SniffJoke doesn't overwrite the default [%s]\n",
			default_cfg
		);
	}
	else {
		printf("= configuration unchanged\n");
	}

	nfds = mitm->tunfd > mitm->netfd ? mitm->tunfd + 1 : mitm->netfd + 1;

	/* main block */
	while(1) 
	{
		FD_ZERO(&infd);
		FD_SET( mitm->tunfd, &infd );
		FD_SET( mitm->netfd, &infd );

		/* tv_usec keep microseconds, I want 0.2 sec of delay */
		timeout.tv_usec = (1000 * 1000 / 5);
		timeout.tv_sec = 0;

		x = select(nfds, &infd, NULL, NULL, &timeout);

		switch(x) 
		{
		case -1:
			check_call_ret("error in I/O select", errno, x);
			return -1;
		case 0:
			webio->web_poll();
			if(sjconf->running->reload_conf) 
			{
				printf("configuration reload...\n");
				refresh_confile = true;

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
			webio->web_poll();
			
			if(FD_ISSET( mitm->tunfd, &infd)) 
				mitm->network_io( TUNNEL, conntrack );

			if(FD_ISSET( mitm->netfd, &infd)) 
				mitm->network_io( NETWORK, conntrack );

			conntrack->analyze_packets_queue();
			mitm->queue_flush( conntrack );
		}
	}
	/* nevah here */
}
