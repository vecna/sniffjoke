#include <iostream>
#include <cerrno>
using namespace std;
#include <unistd.h>
#include <stdarg.h>
#include <stdlib.h>
#include <stdio.h>
#include <getopt.h>
#include <fcntl.h>
#include <pwd.h>
#include <grp.h>
#include <wait.h>
#include <assert.h>

#include <sys/un.h>

#include "sniffjoke.h"

/* Sniffjoke defaults config values */
const char *default_conf_file = "/root/.sniffjoke/sniffjoke.conf";
const char *default_user = "nobody";
const char *default_group = "users";
const char *default_chroot_dir = "/var/run/sniffjoke";
const char *default_log_file = "/sniffjoke.log";
const unsigned int default_debug_level = 0;

const char *prog_name = "SniffJoke, http://www.delirandom.net/sniffjoke";
const char *help_url = "http://www.delirandom.net/sniffjoke";
const char *prog_version = "0.3";

static sj_process_t sj_process_type = SJ_PROCESS_TYPE_UNASSIGNED;
static int sj_srv_father_pid = -1;
static int sj_srv_child_pid = -1;
static int sj_srv_lock;
static struct passwd *userinfo;
static struct group *groupinfo;

/* process configuration, data struct defined in sniffjoke.h */
static struct sj_useropt useropt;

/* Sniffjoke networking and feature configuration */
static SjConf *sjconf;
/* Sniffjoke man in the middle class and functions */
static NetIO *mitm;

static void sj_help(const char *pname);
static void sj_version(const char *pname);

static pid_t sj_read_pid(const char* pidfile);
static int sj_trylock(const char* file);
static int sj_fork();
static void sj_background();
static void sj_daemon_sec();
static void sj_jail();
static void sj_privileges_downgrade();
static void sj_clean_exit(bool exit_request);
static void sj_forced_clean_exit(pid_t pid);
static void sj_sigtrap(int signal);
static int sj_recv_unix_data(int sock, char *databuf, int bufsize, struct sockaddr *from, FILE *error_flow, const char *usermsg);
static int sj_srv_child_prepare_local_unixserv();
static void sj_srv_child_check_local_unixserv(int srvsock, SjConf *confobj);
static void sj_cli_send_command(char *cmdstring);

static void sniffjoke_help(const char *pname) {
	printf(
		"%s [command] or %s --options:\n"
		" --debug [level 1-3]\tenable debug and set the verbosity [default:1]\n"
		" --logfile [file]\tset a logfile, [default %s]\n"
		" --user [username]\tdowngrade priviledge to the specified user [default:nobody]\n"
		" --group [groupname]\tdowngrade priviledge to the specified group [default:users]\n"
		" --chroot-dir [dir]\truns chroted into the specified dir [default:disabled]\n"
		" --force\t\tforce restart if sniffjoke service\n"
		" --foreground\t\trunning in foreground\n"
		" --version\t\tshow sniffjoke version\n"
		" --help\t\t\tshow this help\n\n"
		"while sniffjoke is running, you should send one of those commands as command line argument:\n"
		" start\t\t\tstart sniffjoke hijacking/injection\n"
		" stop\t\t\tstop sniffjoke (but remain tunnel interface active)\n"
		" stat\t\t\tget statistics about sniffjoke configuration and network\n"
		" set start end value\tset per tcp ports the strongness of injection\n"
		"\t\t\tthe values are: [heavy|normal|light|none]\n"
		" clear\t\t\talias to \"set 1 65535 none\"\n"
		" showport\t\tshow TCP ports strongness of injection\n"
		" loglevel\t\t0 = normal, 1 = verbose, 2 = debug\n\n"
		"\t\t\thttp://www.delirandom.net/sniffjoke\n",
		pname, pname, default_log_file, "127.0.0.1");
}

static void sniffjoke_version(const char *pname) {
	printf("%s %s\n", prog_name, prog_version);
}

static pid_t sj_read_pid(const char* pidfile) {
	int ret = 0;
	FILE *pidf = fopen(pidfile, "r");

	if(pidf != NULL) {
		char tmpstr[6];
		if(fgets(tmpstr, 6, pidf) != NULL)
			ret = atoi(tmpstr);
		fclose(pidf);
	}
	
	return ret;
}

static int sj_trylock(const char* file) {
	FILE *ret;
	int fd;
	struct flock fl;
	
	ret = fopen(file, "w+");
	if(ret != NULL) {
		fd = fileno(ret);
	
		fl.l_type   = F_WRLCK;
		fl.l_whence = SEEK_SET;
		fl.l_start  = 0;
		fl.l_len    = 0;
		fl.l_pid    = getpid();
	
		if(fcntl(fd, F_SETLK, &fl) == 0)
			return 0; // Success
		if(fcntl(fd, F_SETLK, &fl) == -1 && (errno == EACCES || errno == EAGAIN))
			return 1; // Just locked
		else
			return -1; // Fail
	}
	
	return -2; // Miserable Fail
}

static void sj_close_fd() {
	int i;
        for (i = getdtablesize(); i >= 0; --i)
                close(i);

	if(useropt.go_foreground == false) {
		i=open("/dev/null",O_RDWR);     /* stdin  */
		dup(i);                         /* stdout */
		dup(i);                         /* stderr */
	}

}

static void sj_background() {

	if(fork())
		exit(0);
		
	sj_close_fd();
	
}

static void sj_process_isolation() {
        setsid();
        umask(0);
}

static int sj_fork() {
	
	assert(sj_process_type == SJ_PROCESS_TYPE_UNASSIGNED);
	
	static FILE *sj_pid_file;

	pid_t pid = fork();
	
	if(pid < 0) {
		return -1;
	}

	if(pid) { // SJ_SRV_FATHER (root process)
		sj_process_type = SJ_PROCESS_TYPE_SRV_FATHER;
		sj_srv_child_pid = pid;
		sj_pid_file = fopen(SJ_SRV_FATHER_PID_FILE, "w+");
		if(sj_pid_file == NULL) {
			internal_log(stderr, ALL_LEVEL, "FATAL ERROR: unable to write %s: %s", SJ_SRV_FATHER_PID_FILE, strerror(errno));
			sj_clean_exit(true);
		} else {
			fprintf(sj_pid_file, "%d", getpid());
			fclose(sj_pid_file);
		}
		
		useropt.logstream = NULL;
		
		waitpid(pid, NULL, 0);
		sj_clean_exit(true);
			
	} else { // SJ_SRV_CHILD (user process)
	
		/* close sj_srv_lock fd on child */
		close(sj_srv_lock);
			
		sj_process_isolation();
		sj_process_type = SJ_PROCESS_TYPE_SRV_CHILD;
		sj_pid_file = fopen(SJ_SRV_CHILD_PID_FILE, "w+");	
		if(sj_pid_file == NULL) {
			internal_log(stderr, ALL_LEVEL, "FATAL ERROR: unable to write %s: %s", SJ_SRV_CHILD_PID_FILE, strerror(errno));
			sj_clean_exit(true);
		} else {
			fprintf(sj_pid_file, "%d", getpid());
			fclose(sj_pid_file);
		}
	}

	return pid;
}

static void sj_jail() {
	chdir(useropt.chroot_dir);
	if(useropt.chroot_dir != NULL && chroot(useropt.chroot_dir)) {
		internal_log(NULL, ALL_LEVEL, "error chrooting into %s: unable to start sniffjoke", useropt.chroot_dir);
		sj_clean_exit(true);		
	}
}

static void sj_privileges_downgrade() {
	if(setgid(groupinfo->gr_gid) || setuid(userinfo->pw_uid)) {
		internal_log(NULL, ALL_LEVEL, "error loosing root privileges: unable to start sniffjoke");
		sj_clean_exit(true);
	}
}

/* used in clean closing */
static void sj_clean_exit(bool exit_request) {
	
	switch(sj_process_type) {
		case SJ_PROCESS_TYPE_SRV_FATHER:
			internal_log(stdout, VERBOSE_LEVEL, "sniffjoke srv father is exiting");
			if(sj_srv_child_pid != -1) {
				internal_log(stdout, VERBOSE_LEVEL, "sniffjoke srv father generated a child possibily still alive, and now is killing him");
				kill(sj_srv_child_pid, SIGTERM);
				/* let the child express his last desire */
				waitpid(sj_srv_child_pid, NULL, 0);
			}
			rmdir(SJ_SRV_TMPDIR);
			unlink(SJ_SRV_LOCK);
			break;
		case SJ_PROCESS_TYPE_SRV_CHILD:
			internal_log(stdout, VERBOSE_LEVEL, "sniffjoke srv child is exiting");
			unlink(SJ_SRV_US);
			break;
		case SJ_PROCESS_TYPE_CLI:
			unlink(SJ_CLI_LOCK);
			break;
		case SJ_PROCESS_TYPE_UNASSIGNED:
		default:
			break;
	}
	
	if(sjconf != NULL) 
		delete sjconf;

	if(mitm != NULL)
		delete mitm;

	if(exit_request)
		exit(1);
}

static void sj_forced_clean_exit(pid_t pid) {
	/* the function return when the process is dead */	
	bool dead = false;
	int killret;
	internal_log(NULL, ALL_LEVEL, "killing process (%d)", pid);

	/* kill! */
	killret = kill(pid, SIGTERM);
	
	while(!dead) {
		if(!killret)
			usleep(50000);
		else if(errno == EPERM) {
			internal_log(NULL, ALL_LEVEL, "you have not privileges to kill process (%d)", pid);
			exit(0);
		} else /* (errno == ESRCH) */ {
			dead = true;
			internal_log(NULL, ALL_LEVEL, "process (%d) is dead", pid);
		}
		
		/* test if the pid is running again */
		killret = kill(pid, SIGUSR1);
	}
}

static void sj_sigtrap(int signal) {
	if(signal)
		internal_log(NULL, ALL_LEVEL, "received signal %d, cleaning sniffjoke objects...", signal);
		
	sj_clean_exit(false);
		
	raise(SIGKILL);
}

/* internal routine called in sj_cli_send_command and sj_srv_child_check_local_unixserv */
static int sj_recv_unix_data(int sock, char *databuf, int bufsize, struct sockaddr *from, FILE *error_flow, const char *usermsg) {

	assert(sj_process_type == SJ_PROCESS_TYPE_SRV_CHILD || sj_process_type == SJ_PROCESS_TYPE_CLI);

	memset(databuf, 0x00, bufsize);

	/* we receive up to bufsize -1 having databuf[bufsize] = 0 and saving us from future segfaults */

	int fromlen = sizeof(struct sockaddr_un), ret;

	if((ret = recvfrom(sock, databuf, bufsize, 0, from, (socklen_t *)&fromlen)) == -1) 
	{
		if(errno == EAGAIN || errno == EWOULDBLOCK) {
			return 0;
		}

		internal_log(error_flow, ALL_LEVEL, "unable to receive local socket: %s: %s", usermsg, strerror(errno));
	}

	return ret;
}

static int sj_srv_child_prepare_local_unixserv() {

		assert(sj_process_type == SJ_PROCESS_TYPE_SRV_CHILD);

		const char *sniffjoke_socket_path = SJ_SRV_US;
		struct sockaddr_un sjsrv;
		int sock;

		if ((sock = socket(AF_UNIX, SOCK_DGRAM, 0)) == -1) {
			internal_log(NULL, ALL_LEVEL, "FATAL ERROR: : unable to open unix socket: %s", strerror(errno));
			sj_clean_exit(true);
		}

		memset(&sjsrv, 0x00, sizeof(sjsrv));
		sjsrv.sun_family = AF_UNIX;
		memcpy(sjsrv.sun_path, sniffjoke_socket_path, strlen(sniffjoke_socket_path));

		if(!access(sniffjoke_socket_path, F_OK)) {
			if(unlink(sniffjoke_socket_path)) {
				internal_log(NULL, ALL_LEVEL, "FATAL ERROR: unable to unlink previous instance of %s: %s", 
				sniffjoke_socket_path, strerror(errno));
				sj_clean_exit(true);
			}
		}
								
		if (bind(sock, (struct sockaddr *)&sjsrv, sizeof(sjsrv)) == -1) {
			close(sock);
			internal_log(NULL, ALL_LEVEL, "FATAL ERROR: unable to bind unix socket %s: %s", 
						 sniffjoke_socket_path, strerror(errno)
			);
			sj_clean_exit(true);
		}

		if(fcntl(sock, F_SETFL, O_NONBLOCK) == -1) {
			close(sock);
			internal_log(NULL, ALL_LEVEL, "FATAL ERROR: unable to set non blocking unix socket %s: %s",
						sniffjoke_socket_path, strerror(errno)
			);

			sj_clean_exit(true);
		}
		internal_log(NULL, VERBOSE_LEVEL, "opened unix socket %s", sniffjoke_socket_path);
		
		return sock;
}

/* function used in in order to receive command and modify the running conf, display stats and so on . */
static void sj_srv_child_check_local_unixserv(int srvsock, SjConf *confobj) {

	assert(sj_process_type == SJ_PROCESS_TYPE_SRV_CHILD);

	char received_command[MEDIUMBUF], *output =NULL, *internal_buf =NULL;
	int i, rlen, cmdlen;
	struct sockaddr_un fromaddr;

	if((rlen = sj_recv_unix_data(srvsock, received_command, MEDIUMBUF, (struct sockaddr *)&fromaddr, NULL, "from the command receiving engine")) == -1) 
		sj_clean_exit(true);

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
	} else if(!memcmp(received_command, "set", strlen("set") )) {
		int start_port, end_port, value;

		/* FIXME - magari supportare set portasingola TIPO, set start:end TIPO, set porta1,porta2,porta3,... TIPO */
		/* FIXME - at the moment only integer value are accepted: 0 1 2 3 4 */
		sscanf(received_command, "set %d %d %d", &start_port, &end_port, &value);

		if(start_port < 0 || start_port > PORTNUMBER || end_port < 0 || end_port > PORTNUMBER || 
			value < 0 || value >= 0x05) 
		{
			internal_buf = (char *)malloc(MEDIUMBUF);
			snprintf(internal_buf, MEDIUMBUF, "invalid port, %d or %d, must be > 0 and < %d",
				start_port, end_port, PORTNUMBER);
			internal_log(NULL, ALL_LEVEL, "%s", internal_buf);
			output = internal_buf;
		}
		else {
			output = sjconf->handle_set_command(start_port, end_port, value);
		}
	} else if (!memcmp(received_command, "clear", strlen("clear") )) {
		output = sjconf->handle_set_command(1, PORTNUMBER, NONE);
	} else if (!memcmp(received_command, "showport", strlen("showport") )) {
		output = sjconf->handle_showport_command();
	} else if (!memcmp(received_command, "loglevel", strlen("loglevel") ))  {
		int loglevel;

		sscanf(received_command, "loglevel %d", &loglevel);
		if(loglevel < 0 || loglevel > HACKS_DEBUG) {
			internal_buf = (char *)malloc(MEDIUMBUF);
			printf("%d\n", loglevel);
			snprintf(internal_buf, MEDIUMBUF, "invalid log value: %d, must be > 0 and < than %d", loglevel, HACKS_DEBUG);
			internal_log(NULL, ALL_LEVEL, "%s", internal_buf);
			output = internal_buf;
		} else {
			output = sjconf->handle_log_command(loglevel);
		}
	} else {
		internal_log(NULL, ALL_LEVEL, "wrong command %s", received_command);
	}

	/* send the answer message to the client */
	if(output != NULL)
		sendto(srvsock, output, strlen(output), 0, (struct sockaddr *)&fromaddr, sizeof(fromaddr));

	if(internal_buf != NULL)
		free(internal_buf);
}

static void sj_cli_send_command(char *cmdstring)  {

	assert(sj_process_type == SJ_PROCESS_TYPE_CLI);

	int sock;
	char received_buf[HUGEBUF];
	struct sockaddr_un servaddr;/* address of server */
	struct sockaddr_un clntaddr;/* address of client */
	struct sockaddr_un from; /* address used for receiving data */
	int rlen;
	
	unlink(SJ_CLI_US);
	   
	/* Create a UNIX datagram socket for client */
	if ((sock = socket(AF_UNIX, SOCK_DGRAM, 0)) == -1) {
		internal_log(NULL, ALL_LEVEL, "FATAL ERROR: unable to open UNIX socket for connect to sniffjoke server: %s", strerror(errno));
		exit(0);
	}
		
	/* Client will bind to an address so the server will get an address in its recvfrom call and use it to
	 * send data back to the client.  
	 */
	memset(&clntaddr, 0x00, sizeof(clntaddr));
	clntaddr.sun_family = AF_UNIX;
	strcpy(clntaddr.sun_path, SJ_CLI_US);

	if (bind(sock, (const sockaddr *)&clntaddr, sizeof(clntaddr)) == -1) {
		internal_log(NULL, ALL_LEVEL, "FATAL ERROR: unable to bind client to %s: %s", SJ_CLI_US, strerror(errno));
		exit(0);
	}

	/* Set up address structure for server socket */
	memset(&servaddr, 0x00, sizeof(servaddr));
	servaddr.sun_family = AF_UNIX;
	strcpy(servaddr.sun_path, SJ_SRV_US);

	if(sendto(sock, cmdstring, strlen(cmdstring), 0, (const struct sockaddr *)&servaddr, sizeof(servaddr)) == -1) {
		internal_log(NULL, ALL_LEVEL, "FATAL ERROR: unable to send message [%s]: %s", cmdstring, strerror(errno));
		exit(0);
	}

	/* We receive a max of HUGEBUF -1 saving us from segfault during printf */
	if((rlen = sj_recv_unix_data(sock, received_buf, HUGEBUF, (struct sockaddr *)&from, stdout, "from the command sending engine")) == -1) 
		exit(0); // the error message has been delivered 

	if(rlen == 0)
		internal_log(NULL, ALL_LEVEL, "unreceived response for the command [%s]", cmdstring);
	else	/* the output */
		printf("answer reiceved from sniffjoke service:\n\n%s\n", received_buf);
	
	close(sock);
	
	unlink(SJ_CLI_LOCK);
}

void check_call_ret(const char *umsg, int objerrno, int ret, bool fatal) {
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
                sj_clean_exit(true);
        } else {
                internal_log(NULL, ALL_LEVEL, "error: %s", errbuf);
        }
}

/* forceflow is almost useless, use NULL in the normal logging options */
void internal_log(FILE *forceflow, int errorlevel, const char *msg, ...) {
        va_list arguments;
        time_t now = time(NULL);
        FILE *output_flow;

        if(forceflow == NULL && useropt.logstream == NULL)
                return;

        if(forceflow != NULL)
                output_flow = forceflow;
        else
                output_flow = useropt.logstream;

        if(errorlevel == PACKETS_DEBUG && useropt.packet_logstream != NULL)
                output_flow = useropt.packet_logstream;

        if(errorlevel == HACKS_DEBUG && useropt.hacks_logstream != NULL)
                output_flow = useropt.hacks_logstream;

        if(errorlevel <= useropt.debug_level) {
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

int main(int argc, char **argv) {
	int i, charopt, local_input = 0;
	bool restart_on_restore = false;
	char command_buffer[MEDIUMBUF], *command_input = NULL;
	bool srv_just_active = 0;
	int listening_unix_socket;
	
	/* set the default values in the configuration struct */
	useropt.force_restart = false;
	useropt.go_foreground = false;
	useropt.cfgfname = default_conf_file;
	useropt.user = default_user;
	useropt.group = default_group;
	useropt.chroot_dir = default_chroot_dir;
	useropt.logfname = default_log_file;
	useropt.debug_level = default_debug_level;
	useropt.logstream = stdout;

	struct option sj_option[] =
	{
		{ "conf", required_argument, NULL, 'f' },
		{ "user", required_argument, NULL, 'u' },
		{ "group", required_argument, NULL, 'g' },
		{ "chroot-dir", required_argument, NULL, 'c' },
		{ "debug", required_argument, NULL, 'd' },
		{ "logfile", required_argument, NULL, 'l' },
		{ "foreground", optional_argument, NULL, 'x' },
		{ "force", optional_argument, NULL, 'r' },
		{ "version", optional_argument, NULL, 'v' },
		{ "help", optional_argument, NULL, 'h' },
		{ NULL, 0, NULL, 0 }
	};

	if(getuid() || geteuid()) {
		printf("sniffjoke for running require root privileges\n");
		sniffjoke_help(argv[0]);
		return 0;
	}
	
	memset(command_buffer, 0x00, MEDIUMBUF);
	/* check for direct commands */
	if ( (argc >= 2) && !memcmp(argv[1], "start", strlen("start") )) {
		snprintf(command_buffer, MEDIUMBUF, "start");
		command_input = argv[1];
	}
	if ( (argc >= 2) && !memcmp(argv[1], "stop", strlen("stop") )) {
		snprintf(command_buffer, MEDIUMBUF, "stop");
		command_input = argv[1];
	}
	if ( (argc >= 2) && !memcmp(argv[1], "stat", strlen("stat") )) {
		snprintf(command_buffer, MEDIUMBUF, "stat");
		command_input = argv[1];
	}
	if ( (argc == 5) && !memcmp(argv[1], "set", strlen("set") )) {
		snprintf(command_buffer, MEDIUMBUF, "set %s %s %s", argv[2], argv[3], argv[4]);
		command_input = command_buffer;
	} 
	if ( (argc == 2) && !memcmp(argv[1], "clear", strlen("clear") )) {
		snprintf(command_buffer, MEDIUMBUF, "clear");
		command_input = command_buffer;
	} 
	if ( (argc == 2) && !memcmp(argv[1], "showport", strlen("showport") )) {
		snprintf(command_buffer, MEDIUMBUF, "showport");
		command_input = command_buffer;
	} 
	if ( (argc == 3) && !memcmp(argv[1], "loglevel", strlen("loglevel") )) {
		snprintf(command_buffer, MEDIUMBUF, "loglevel %s", argv[2]);
		command_input = command_buffer;
	}
	
	if( command_input == NULL) {
		while((charopt = getopt_long(argc, argv, "f:u:g:c:l:d:xrvh", sj_option, NULL)) != -1) {
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
					sniffjoke_version(argv[0]);
					return 0;
				case 'h':
				default:
					sniffjoke_help(argv[0]);
					return -1;

				argc -= optind;
				argv += optind;
			}
		}
		
		if(!useropt.go_foreground)
			sj_background();
		else {
			useropt.logstream = stdout;
			internal_log(NULL, ALL_LEVEL, "foreground running: logging set on standard output, block with ^c");
		}

		sj_process_isolation();
	}

	/* sj_trylock 1/2, works also as a first test on server activity
	 *
	 * taking the lock after the background evaluation is fundamentl because in a fork the child does not inherit
	 * parent's locks so the locks would be released after parent death. */

	sj_srv_lock = sj_trylock(SJ_SRV_LOCK);
	switch(sj_srv_lock) {
		case 0:	/* Success */
				break;
		case 1: /* Just Locked */
				srv_just_active = true;
				break;
		case -1: /* Fail */
		case -2: /* Miserable Fail */
		default: /* There are no other cases, so this is a spectacular fail */
				internal_log(NULL, ALL_LEVEL, "FATAL ERROR: we are unable to acquire server lock: %s", SJ_SRV_LOCK);
				exit(0);
				break;	
	}	

	/* understand if the usage is client-like or service-like */
	if(command_input != NULL) 
	{
		sj_process_type = SJ_PROCESS_TYPE_CLI;
		if(srv_just_active) {
			switch(sj_trylock(SJ_CLI_LOCK)) {
				case 0:	 // Success
						break;
				case 1:  // Just Locked
						internal_log(NULL, ALL_LEVEL, "an other client is active, exiting");
						exit(0);
						break;
				case -1: // Fail
				case -2: // Miserable Fail
				default: // There are no other cases, so this is a spectacular fail
						internal_log(NULL, ALL_LEVEL, "FATAL ERROR: unable to acquire client lock: %s", SJ_CLI_LOCK);
						exit(0);
						break;
			}
			
			/* force to read user and group in confi file */
		        useropt.user = NULL;
		        useropt.group = NULL;	
			sjconf = new SjConf( &useropt );
			
			userinfo = getpwnam(sjconf->running->user);
			groupinfo = getgrnam(sjconf->running->group);
			
			if(userinfo == NULL || groupinfo == NULL) {
				internal_log(NULL, ALL_LEVEL, "invalid user or group specified: %s, %s", sjconf->running->user, sjconf->running->group);
				return -1;
			}
			
			sj_jail();
			
			sj_privileges_downgrade();
			
			internal_log(NULL, ALL_LEVEL, "sending command: [%s] to sniffjoke service", command_input);
			sj_cli_send_command(command_input);
			/* KKK: not clean_pidfile because the other process must continue to run,
			 * and not _sigtrap because there are not obj instanced */
			return 0;
		} else {
			internal_log(NULL, ALL_LEVEL, "warning: sniffjoke is not running, command  %s ignored", command_input);
			return 0;
		}
	}

	if(argc > 1 && argv[1][0] != '-') {
		internal_log(stderr, ALL_LEVEL, "wrong usage of sniffjoke: beside commands, only --long-opt are accepted");
		sniffjoke_help(argv[0]);
		return -1;
	}

	if(srv_just_active) {
		if(useropt.force_restart) {
			sj_srv_father_pid = sj_read_pid(SJ_SRV_FATHER_PID_FILE);
			sj_srv_child_pid = sj_read_pid(SJ_SRV_CHILD_PID_FILE);

			if(sj_srv_father_pid) {
				sj_forced_clean_exit(sj_srv_father_pid);
				internal_log(NULL, VERBOSE_LEVEL, "forced kill of srv father %d process...", sj_srv_father_pid);
			}
			if(sj_srv_child_pid) {
				sj_forced_clean_exit(sj_srv_child_pid);
				internal_log(NULL, VERBOSE_LEVEL, "forced kill of srv child %d process...", sj_srv_child_pid);
			}
			
			/* sj_lock 2/2, works also as a second test on server activity */
			sj_srv_lock = sj_trylock(SJ_SRV_LOCK);
			switch(sj_srv_lock) {
				case 0:	/* Success */
						break;
				case 1: /* Just Locked */
						internal_log(stderr, ALL_LEVEL, "FATAL ERROR: srv killed but probably an other srv has been run");						
						exit(0);
						break;
				case -1: /* Fail */
				case -2: /* Miserable Fail */
				default: /* There are no other cases, so this is a spectacular fail */
						internal_log(stderr, ALL_LEVEL, "FATAL ERROR: we are unable to acquire server lock: %s", SJ_SRV_LOCK);
						exit(0);
						break;	
			}			
		} else {
			internal_log(stderr, ALL_LEVEL, "sniffjoke is already running, use --force or check --help");
			/* same reason of KKK before */
			return 0;
		}
	}
	
	/* If we are here we have the lock on SJ_SRV_LOCK so we can remove the temporary dir SJ_SRV_TMPDIR*/
	rmdir(SJ_SRV_TMPDIR);
	mkdir(SJ_SRV_TMPDIR, 644);
	/* checking config file */
	if(useropt.cfgfname != NULL && access(useropt.cfgfname, W_OK)) {
		internal_log(NULL, ALL_LEVEL, "unable to access %s: sniffjoke will use the defaults", useropt.cfgfname);
	}
	
	/* setting ^C, SIGTERM and other signal trapped for clean network environment */
	signal(SIGINT, sj_sigtrap);
	signal(SIGABRT, sj_sigtrap);
	signal(SIGTERM, sj_sigtrap);
	signal(SIGQUIT, sj_sigtrap);
	signal(SIGUSR1, SIG_IGN);

	/* initialiting object configuration */
	sjconf = new SjConf( &useropt );

	userinfo = getpwnam(sjconf->running->user);
	groupinfo = getgrnam(sjconf->running->group);

	if(userinfo == NULL || groupinfo == NULL) {
		internal_log(stderr, ALL_LEVEL, "invalid user or group specified: %s %s", useropt.user, useropt.group);
		return -1;
	}

	/* the code flow reach here, SniffJoke is ready to instance network environment */
	mitm = new NetIO( sjconf );

	if(mitm->is_network_down())
	{
		internal_log(stderr, ALL_LEVEL, "detected network error in NetIO constructor: unable to start sniffjoke");
		sj_clean_exit(true);
	}

	if(sj_fork() == -1) {
		internal_log(stderr, ALL_LEVEL, "fatal: unable to fork sniffjoke server: %s", strerror(errno));
		sj_clean_exit(true);
	}
	
	sj_jail();

	if(!useropt.go_foreground) {	
		if((useropt.logstream = fopen(useropt.logfname, "a+")) == NULL) {
			internal_log(stderr, ALL_LEVEL, "FATAL ERROR: unable to open %s: %s", useropt.logfname, strerror(errno));
			sj_clean_exit(true);
		}
			
		if(useropt.debug_level >= PACKETS_DEBUG) {
			char *tmpfname = (char *)malloc(strlen(useropt.logfname) + 10);
			sprintf(tmpfname, "%s.packets", useropt.logfname);
			if((useropt.packet_logstream = fopen(tmpfname, "a+")) == NULL) {
				internal_log(stderr, ALL_LEVEL, "FATAL ERROR: unable to open %s: %s", tmpfname, strerror(errno));
				sj_clean_exit(true);
			} 
			internal_log(NULL, ALL_LEVEL, "opened for packets debug: %s successful", tmpfname);
		}

		if(useropt.debug_level >= HACKS_DEBUG) {
			char *tmpfname = (char *)malloc(strlen(useropt.logfname) + 10);
			sprintf(tmpfname, "%s.hacks", useropt.logfname);
			if((useropt.hacks_logstream = fopen(tmpfname, "a+")) == NULL) {
				internal_log(stderr, ALL_LEVEL, "FATAL ERROR: unable to open %s: %s", tmpfname, strerror(errno));
				sj_clean_exit(true);
			}
			internal_log(NULL, ALL_LEVEL, "opened for hacks debug: %s successful", tmpfname);
		}
	}
	
	sj_privileges_downgrade();
	
	listening_unix_socket = sj_srv_child_prepare_local_unixserv();
	
	if(sjconf->running->sj_run == false)
		internal_log(NULL, ALL_LEVEL, "sniffjoke is running and INACTIVE: use \"sniffjoke start\" command to start it\n");

	/* main block */
	while(1) {
		mitm->network_io();
		mitm->queue_flush();

		if(mitm->is_network_down() && sjconf->running->sj_run == true) {
			internal_log(NULL, ALL_LEVEL, "Network is down, interrupting sniffjoke");
			sjconf->running->sj_run = false;
			restart_on_restore = true;
		}

		if(!mitm->is_network_down() && restart_on_restore == true) {
			internal_log(NULL, ALL_LEVEL, "Network restored, restarting sniffjoke");
			sjconf->running->sj_run = true;
			restart_on_restore = false;
		}
		
		sj_srv_child_check_local_unixserv(listening_unix_socket, sjconf);

	}
	/* nevah here */
}
