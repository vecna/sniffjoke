#include <iostream>
#include <cerrno>
using namespace std;
#include <string.h>
#include <sys/time.h>
#include <unistd.h>
#include <signal.h>
#include <stdlib.h>
#include <sys/select.h>
#include <sys/types.h>

#include "sniffjoke.h"

const char *default_cfg = "/etc/sniffjoke.conf";
const char *prog_name = "SniffJoke, http://www.delirandom.net/sniffjoke";
const char *help_url = "http://www.delirandom.net/sniffjoke";
const char *prog_version = "0.3";

static SjConf *sjconf;
static NetIO *mitm;
static WebIO *webio;
static TCPTrack *conntrack;

static void sniffjoke_help(const char *pname) {
	printf("%s [config file]\n", pname);
	printf(" default config file is %s\n", pname);
	printf("%s -v print sniffjoke version\n", pname);
	printf("info and example: %s\n", help_url);
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

int main(int argc, const char **argv) {
	const char *cfg =NULL;
	fd_set infd;
	int x, nfds;
	struct timeval timeout;
	bool refresh_confile = false;

	if(argc != 1) 
	{
		if(strstr(argv[1], "-h") ) {
			sniffjoke_help(argv[0]);
			return -1;
		}

		if(strstr(argv[1], "-v") ) {
			sniffjoke_version(argv[0]);
			return 0;
		}

		cfg = argv[1];
	}

	if(getuid() || geteuid()) 
		check_call_ret("required root privileges", EPERM, -1, NULL, NULL);

	/* setting ^C, SIGTERM and other signal trapped for clean network environment */
	signal(SIGINT, sniffjoke_sigtrap);
	signal(SIGABRT, sniffjoke_sigtrap);
	signal(SIGTERM, sniffjoke_sigtrap);
	signal(SIGQUIT, sniffjoke_sigtrap);

	sjconf = new SjConf( cfg ? cfg : default_cfg );
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
	if(refresh_confile && cfg != NULL) {
		sjconf->dump_config( cfg );
	}
	else if(cfg == NULL) {
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
