#include <iostream>
#include <iostream>
#include <cerrno>
using namespace std;
#include <string.h>
#include <unistd.h>
#include <signal.h>
#include <stdlib.h>
#include <getopt.h>
#include <fcntl.h>
#include <pwd.h>
#include <grp.h>
#include <wait.h>

#include <netinet/in.h>

#include <sys/types.h>
#include <sys/time.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/un.h>

#include "sniffjoke.h"

/* Sniffjoke defaults config values */
const char *default_conf_file = "/root/.sniffjoke/sniffjoke.conf";
const int default_web_bind_port = 8844;
const char *default_user = "nobody";
const char *default_group = "users";
const char *default_chroot_dir = "/var/run/sniffjoke";
const char *default_log_file = "/sniffjoke.log";
unsigned int default_debug_level = 0;


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
static struct passwd *userinfo;
static struct group *groupinfo;
static struct sj_useropt useropt;
static int listening_socket;
static FILE *sniffjoke_father_pid_file = NULL;
static FILE *sniffjoke_child_pid_file = NULL;
static int father = -1;
static int child = -1;

static void sniffjoke_help(const char *pname);
static void sniffjoke_version(const char *pname);
static void kill_and_clean_pidfile(const char * pidfile);
static void sniffjoke_sigtrap(int signal);
static void clean_exit(bool exit_request);
void check_call_ret(const char *umsg, int objerrno, int ret, bool fatal);
void internal_log(FILE *forceflow, int errorlevel, const char *msg, ...);
static int receive_unix_data(int sock, char *databuf, int bufsize, struct sockaddr *from, FILE *error_flow, const char *usermsg);
static void check_local_unixserv(int srvsock, SjConf *confobj);
static int sniffjoke_fork();
static void sniffjoke_background();
static pid_t sniffjoke_is_running(const char* pidfile);
static void send_command(char *cmdstring, pid_t srvpid);
FILE* sniff_lock(const char* file);

static void sniffjoke_help(const char *pname) {
	printf(
		"%s [command] or %s --options:\n"
		" --debug [level 1-3]\tenable debug and set the verbosity [default:1]\n"
		" --logfile [file]\tset a logfile, [default %s]\n"
		" --bind-port [port]\tset the port where bind management webserver [default:%d]\n"
		" --bind-addr [addr]\tset interface where bind management webserver [default:%s]\n"
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
		" log level\t\t0 = normal, 1 = verbose, 2 = debug\n\n"
		"\t\t\thttp://www.delirandom.net/sniffjoke\n",
	pname, pname, default_log_file, default_web_bind_port, "127.0.0.1");
}

static void sniffjoke_version(const char *pname) {
	printf("%s %s\n", prog_name, prog_version);
}

static void kill_and_clean_pidfile(const char * pidfile) {
	if(!access(pidfile, R_OK)) {
		FILE *oldpidf = fopen(pidfile, "r");
		char oldpid_string[6];
		int oldpid;

		if(oldpidf == NULL) {
			internal_log(NULL, ALL_LEVEL, "unable to open %s: %s", pidfile, strerror(errno));
			return;
		}

		fgets(oldpid_string, 6, oldpidf);
		fclose(oldpidf);
		
		oldpid = atoi(oldpid_string);

		internal_log(NULL, VERBOSE_LEVEL, "old SNIFFJOKE_PID_FILE %s had pid %d inside, sending sigterm...", pidfile, oldpid);
		
		/* do not suicide! */
		if(oldpid != getpid())
			kill(oldpid, SIGTERM);

	} else {
		internal_log(NULL, ALL_LEVEL, "unable to access %s file, request for unlinking from process %d: %s", pidfile, getpid(), strerror(errno));
	}

	if(!unlink(pidfile)) {
		internal_log(stdout, DEBUG_LEVEL, "unlinked %s as requested", pidfile);
	} else {
		internal_log(stdout, ALL_LEVEL, "unable to unlink %s: %s", pidfile, strerror(errno));
		/* and ... ? */
	}
}

static void sniffjoke_sigtrap(int signal) {
	if(signal)
		internal_log(NULL, ALL_LEVEL, "received signal %d, cleaning sniffjoke objects...", signal);

	if(sjconf != NULL) 
		delete sjconf;

	if(webio != NULL) 
		delete webio;

	if(mitm != NULL)
		delete mitm;
		
	clean_exit(false);
		
	raise(SIGKILL);
}

/* used in clean closing */
static void clean_exit(bool exit_request) {
	/* a father want to kill his child in a cleany way letting him express last desire.
	 * don't try this at home! */
	int uid, euid;
	uid = getuid();
	euid = geteuid();
	if(father != -1 && child != -1) {
		if(!(uid || euid) && uid == father) {
			/* i'm father */
			internal_log(stdout, VERBOSE_LEVEL, "sniffjoke father is exiting");
			if(child != -1) {
				internal_log(stdout, VERBOSE_LEVEL, "sniffjoke child is alive, father is killing him");
				kill(child, SIGTERM);
				/* let the son express his last desire */
				waitpid(child, NULL, 0);
			}
			unlink(SNIFFJOKE_CHILD_PID_FILE);
			unlink(SNIFFJOKE_CHILD_LOCK);
			unlink(SNIFFJOKE_FATHER_PID_FILE);
			unlink(SNIFFJOKE_FATHER_LOCK);
		} else {
			/* i'm child before or after privileges downgrade  */
			internal_log(stdout, VERBOSE_LEVEL, "sniffjoke child is exiting");
			unlink(SNIFFJOKE_SRV_US);
		}
	}

	/* this is the clean way for exit, because sniffjoke_sigtrap delete the instance c++ obj */
	if(exit_request)
		sniffjoke_sigtrap(0);
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
		clean_exit(true);
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

/* internal routine called in send_command and check_local_unixserv */
static int receive_unix_data(int sock, char *databuf, int bufsize, struct sockaddr *from, FILE *error_flow, const char *usermsg) {
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

/* function used in in order to receive command and modify the running conf, display stats and so on . */
static void check_local_unixserv(int srvsock, SjConf *confobj) {
	char received_command[MEDIUMBUF], *output =NULL, *internal_buf =NULL;
	int i, rlen, cmdlen;
	struct sockaddr_un fromaddr;

	memset(received_command, 0x00, MEDIUMBUF);
	if((rlen = receive_unix_data(srvsock, received_command, MEDIUMBUF, (struct sockaddr *)&fromaddr, NULL, "from the command receiving engine")) == -1) 
		clean_exit(true);

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
	} else if (!memcmp(received_command, "log", strlen("log") ))  {
		int loglevel;

		sscanf(received_command, "log %d", &loglevel);
		if(loglevel < 0 || loglevel > HACKS_DEBUG) {
			internal_buf = (char *)malloc(MEDIUMBUF);
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

static int sniffjoke_fork() {
	father = getuid();
	pid_t pid = fork();
	
	if(pid < 0) {
		return -1;
	}

	if(pid) { // FATHER (root process)
		child = pid;
		sniff_lock(SNIFFJOKE_FATHER_LOCK);
		if(sniffjoke_father_pid_file == NULL)
			sniffjoke_father_pid_file = fopen(SNIFFJOKE_FATHER_PID_FILE, "w+");
		if(sniffjoke_father_pid_file == NULL) {
			internal_log(stderr, ALL_LEVEL, "FATAL ERROR: unable to write %s: %s", sniffjoke_father_pid_file, strerror(errno));
			clean_exit(true);
		} else {
			fprintf(sniffjoke_father_pid_file, "%d", getpid());
			fclose(sniffjoke_father_pid_file);
		}
		
		useropt.logstream = NULL;
		
		waitpid(pid, NULL, 0);
		clean_exit(true);
			
	} else { // CHILD (user process)
	    child = getuid();
		sniff_lock(SNIFFJOKE_CHILD_LOCK);
		if(sniffjoke_child_pid_file == NULL)
			sniffjoke_child_pid_file = fopen(SNIFFJOKE_CHILD_PID_FILE, "w+");	
		if(sniffjoke_child_pid_file == NULL) {
			internal_log(stderr, ALL_LEVEL, "FATAL ERROR: unable to write %s: %s", sniffjoke_child_pid_file, strerror(errno));
			clean_exit(true);
		} else {
			fprintf(sniffjoke_child_pid_file, "%d", getpid());
			fclose(sniffjoke_child_pid_file);
		}
	}

	return pid;
}

static void prepare_listening_socket() {
		const char *sniffjoke_socket_path = SNIFFJOKE_SRV_US;
		struct sockaddr_un sjsrv;
		int sock;

		if ((sock = socket(AF_UNIX, SOCK_DGRAM, 0)) == -1) {
			internal_log(NULL, ALL_LEVEL, "fatal: unable to open unix socket: %s", strerror(errno));
			clean_exit(true);
		}

		memset(&sjsrv, 0x00, sizeof(sjsrv));
		sjsrv.sun_family = AF_UNIX;
		memcpy(sjsrv.sun_path, sniffjoke_socket_path, strlen(sniffjoke_socket_path));

		if(!access(sniffjoke_socket_path, F_OK)) {
			if(unlink(sniffjoke_socket_path)) {
				internal_log(NULL, ALL_LEVEL, "fatal: unable to unlink previous instance of %s: %s", 
				sniffjoke_socket_path, strerror(errno));
				clean_exit(true);
			}
		}
								
		if (bind(sock, (struct sockaddr *)&sjsrv, sizeof(sjsrv)) == -1) {
			close(sock);
			internal_log(NULL, ALL_LEVEL, "fatal: unable to bind unix socket %s: %s", 
						 sniffjoke_socket_path, strerror(errno)
			);
			clean_exit(true);
		}

		if(fcntl(sock, F_SETFL, O_NONBLOCK) == -1) {
			close(sock);
			internal_log(NULL, ALL_LEVEL, "fatal: unable to set non blocking unix socket %s: %s",
						sniffjoke_socket_path, strerror(errno)
			);

			clean_exit(true);
		}
		internal_log(NULL, VERBOSE_LEVEL, "opened unix socket %s", sniffjoke_socket_path);
		listening_socket = sock;	
}

static void jailme() {
	/* chroot to the specified dir */
	chdir(useropt.chroot_dir);
	if(useropt.chroot_dir != NULL && chroot(useropt.chroot_dir)) {
		internal_log(NULL, ALL_LEVEL, "error chrooting into %s: unable to start sniffjoke", useropt.chroot_dir);
		clean_exit(true);		
	}
}

static void downgrade_privileges() {
	if(setgid(groupinfo->gr_gid) || setuid(userinfo->pw_uid)) {
		internal_log(NULL, ALL_LEVEL, "error loosing root privileges: unable to start sniffjoke");
		clean_exit(true);
	}
}

static void sniffjoke_background() {
	if(fork())
		exit(0);
}
		
static pid_t sniffjoke_is_running(const char* pidfile) {
	FILE *pidf = fopen(pidfile, "r");
	pid_t potenctial_pid;
	int killret;

	if(pidf != NULL) {
		char tmpstr[6];
		fgets(tmpstr, 6, pidf);
		fclose(pidf);
		potenctial_pid = atoi(tmpstr);
	} else
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
			internal_log(NULL, ALL_LEVEL, "the file %s contains information about a dead process (%d)", pidfile, potenctial_pid);
			if(strcmp(pidfile, SNIFFJOKE_FATHER_PID_FILE)) {
				unlink(SNIFFJOKE_FATHER_LOCK);			
			} else if(strcmp(pidfile, SNIFFJOKE_CHILD_PID_FILE)) {
				unlink(SNIFFJOKE_SRV_US);
				unlink(SNIFFJOKE_CHILD_LOCK);
			}
			return 0;
		}
	}
}

static void send_command(char *cmdstring, pid_t srvpid)  {
	int sock;
	char received_buf[HUGEBUF];
	struct sockaddr_un servaddr;/* address of server */
	struct sockaddr_un clntaddr;/* address of client */
	struct sockaddr_un from; /* address used for receiving data */
	int rlen;
	   
	/* Create a UNIX datagram socket for client */
	if ((sock = socket(AF_UNIX, SOCK_DGRAM, 0)) == -1) {
		internal_log(NULL, ALL_LEVEL, "unable to open UNIX socket for connect to sniffjoke server: %s", strerror(errno));
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
		internal_log(NULL, ALL_LEVEL, "unable to bind client to %s: %s", SNIFFJOKE_CLI_US, strerror(errno));
		exit(0);
	}

	/* Set up address structure for server socket */
	memset(&servaddr, 0x00, sizeof(servaddr));
	servaddr.sun_family = AF_UNIX;
	strcpy(servaddr.sun_path, SNIFFJOKE_SRV_US);

	if(sendto(sock, cmdstring, strlen(cmdstring), 0, (const struct sockaddr *)&servaddr, sizeof(servaddr)) == -1) {
		internal_log(NULL, ALL_LEVEL, "unable to send message [%s]: %s", cmdstring, strerror(errno));
		exit(0);
	}

	if((rlen = receive_unix_data(sock, received_buf, HUGEBUF, (struct sockaddr *)&from, stdout, "from the command sending engine")) == -1) 
		exit(0); // the error message has been delivered 

	if(rlen == 0)
		internal_log(NULL, ALL_LEVEL, "unreceived responde from command [%s]", cmdstring);
	else	/* the output */
		printf("answer reiceved from sniffjoke service running at %d:\n%s\n", srvpid, received_buf);
	
		unlink(SNIFFJOKE_CLI_US);
		close(sock);
}

FILE* sniff_lock(const char* file) {
	FILE *ret;
	int fd;
	struct flock fl;
	
	ret = fopen(file, "w+");
	fd = fileno(ret);
	
	fl.l_type   = F_WRLCK;
	fl.l_whence = SEEK_SET;
	fl.l_start  = 0;
	fl.l_len    = 0;
	fl.l_pid    = getpid();
	
	fcntl(fd, F_SETLKW, &fl);
	
	return ret;
}

int main(int argc, char **argv) {
	int i, charopt, local_input = 0;
	time_t next_web_poll;
	bool restart_on_restore = false;
	char command_buffer[MEDIUMBUF], *command_input = NULL;
	
	/* set the default values in the configuration struct */
	useropt.force_restart = false;
	useropt.go_foreground = false;
	useropt.cfgfname = default_conf_file;
	useropt.bind_port = default_web_bind_port;
	useropt.bind_addr = NULL;
	useropt.user = default_user;
	useropt.group = default_group;
	useropt.chroot_dir = default_chroot_dir;
	useropt.logfname = default_log_file;
	useropt.debug_level = default_debug_level;
	useropt.logstream = stdout;

	struct option sj_option[] =
	{
		{ "conf", required_argument, NULL, 'f' },
		{ "bind-port", required_argument, NULL, 'p' },
		{ "bind-addr", required_argument, NULL, 'a' },
		{ "user", optional_argument, NULL, 'u' },
		{ "group", optional_argument, NULL, 'g' },
		{ "chroot-dir", optional_argument, NULL, 'c' },
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
	
	/* check if sniffjoke is running in background */
	pid_t sniffjoke_father = sniffjoke_is_running(SNIFFJOKE_FATHER_PID_FILE);
	pid_t sniffjoke_child = sniffjoke_is_running(SNIFFJOKE_CHILD_PID_FILE);

	/* understand if the usage is client-like or service-like */
	if(command_input != NULL) 
	{
		if(sniffjoke_child)
		{
			sjconf = new SjConf( &useropt );
			
			userinfo = getpwnam(sjconf->running->user);
			groupinfo = getgrnam(sjconf->running->group);
			
			if(userinfo == NULL || groupinfo == NULL) {
				internal_log(NULL, ALL_LEVEL, "invalid user or group specified: %s, %s", sjconf->running->user, sjconf->running->group);

				return -1;
			}
			
			jailme();
			
			downgrade_privileges();
			
			internal_log(NULL, ALL_LEVEL, "sending command: [%s] to sniffjoke service", command_input);
			send_command(command_input, sniffjoke_child);
			/* KKK: not clean_exit because the other process must continue to run,
			 * and not _sigtrap because there are not obj instanced */
			return 0;
		}
		else {
			internal_log(NULL, ALL_LEVEL, "warning: sniffjoke is not running, command  %s ignored", command_input);
			return 0; // or:
			/* the running proceeding */
		}
	}

	if(argc > 1 && argv[1][0] != '-') {
		internal_log(NULL, ALL_LEVEL, "wrong usage of sniffjoke: beside commands, only --long-opt are accepted");
		sniffjoke_help(argv[0]);
		return -1;
	}

	while((charopt = getopt_long(argc, argv, "fapugcldxrvh", sj_option, NULL)) != -1)
	{
		switch(charopt) {
			case 'f':
				useropt.cfgfname = strdup(optarg);
				break;
			case 'a':
				useropt.bind_addr = strdup(optarg);
				break;
			case 'p':
				useropt.bind_port = atoi(optarg);
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

	if((sniffjoke_father || sniffjoke_child) && !useropt.force_restart) {
		internal_log(NULL, ALL_LEVEL, "sniffjoke is already running, use --force or check --help");
		/* same reason of KKK before */
		return 0;
	}

	/* checking config file */
	if(useropt.cfgfname != NULL && access(useropt.cfgfname, W_OK)) {
		internal_log(NULL, ALL_LEVEL, "unable to access %s: sniffjoke will use the defaults", useropt.cfgfname);
	}

	userinfo = getpwnam(useropt.user);
	groupinfo = getgrnam(useropt.group);
	if(userinfo == NULL || groupinfo == NULL) {
		internal_log(NULL, ALL_LEVEL, "invalid user or group specified: %s %s", useropt.user, useropt.group);
		return -1;
	}
		
	/* bind addr */
	if(useropt.bind_addr != NULL) {
		// FIXME
		internal_log(NULL, ALL_LEVEL, "warning: --bind-addr is IGNORED at the moment: %s\n", useropt.bind_addr);
	}

	/* after the privilege checking */
	if(useropt.force_restart) {
		if(sniffjoke_father) {
			kill(sniffjoke_father, SIGTERM);
			internal_log(NULL, VERBOSE_LEVEL, "sniffjoke remove previous SNIFFJOKESRV_PID_FILE and killed %d process...", sniffjoke_father);
		}
		if(sniffjoke_child) {
			kill(sniffjoke_child, SIGTERM);
			internal_log(NULL, VERBOSE_LEVEL, "sniffjoke remove previous SNIFFJOKE_PID_FILE and killed %d process...", sniffjoke_child);
		}
	}
	
	/* setting ^C, SIGTERM and other signal trapped for clean network environment */
	signal(SIGINT, sniffjoke_sigtrap);
	signal(SIGABRT, sniffjoke_sigtrap);
	signal(SIGTERM, sniffjoke_sigtrap);
	signal(SIGQUIT, sniffjoke_sigtrap);
	signal(SIGUSR1, SIG_IGN);
	
	/* initialiting object configuration */
	sjconf = new SjConf( &useropt );

	/* the code flow reach here, SniffJoke is ready to instance network environment */
	mitm = new NetIO( sjconf );

	if(mitm->networkdown_condition)
	if(mitm->networkdown_condition)
	{
		internal_log(NULL, ALL_LEVEL, "detected network error in NetIO constructor: unable to start sniffjoke");
		clean_exit(true);
	}

	/* setting logfile, debug level, background running */
	if(!useropt.go_foreground)
		sniffjoke_background();
	else {
		useropt.logstream = stdout;
		internal_log(NULL, ALL_LEVEL, "foreground running: logging set on standard output, block with ^c");
	}
		
	if(sniffjoke_fork() == -1) {
		internal_log(NULL, ALL_LEVEL, "fatal: unable to fork sniffjoke server: %s", strerror(errno));
		clean_exit(true);
	}
	
	jailme();

	if(!useropt.go_foreground) {	
		if((useropt.logstream = fopen(useropt.logfname, "a+")) == NULL) {
			internal_log(NULL, ALL_LEVEL, "FATAL ERROR: unable to open %s: %s", useropt.logfname, strerror(errno));
			clean_exit(true);
		}
			
		if(useropt.debug_level >= PACKETS_DEBUG) {
			char *tmpfname = (char *)malloc(strlen(useropt.logfname) + 10);
			sprintf(tmpfname, "%s.packets", useropt.logfname);
			if((useropt.packet_logstream = fopen(tmpfname, "a+")) == NULL) {
				internal_log(NULL, ALL_LEVEL, "FATAL ERROR: unable to open %s: %s", tmpfname, strerror(errno));
				clean_exit(true);
			} 
			internal_log(NULL, ALL_LEVEL, "opened for packets debug: %s successful", tmpfname);
		}

		if(useropt.debug_level >= HACKS_DEBUG) {
			char *tmpfname = (char *)malloc(strlen(useropt.logfname) + 10);
			sprintf(tmpfname, "%s.hacks", useropt.logfname);
			if((useropt.hacks_logstream = fopen(tmpfname, "a+")) == NULL) {
				internal_log(NULL, ALL_LEVEL, "FATAL ERROR: unable to open %s: %s", tmpfname, strerror(errno));
				clean_exit(true);
			}
			internal_log(NULL, ALL_LEVEL, "opened for hacks debug: %s successful", tmpfname);
		}
	}
	
	downgrade_privileges();
	
	prepare_listening_socket();
	
	//webio = new WebIO( sjconf );
	if(sjconf->running->sj_run == false) {
		internal_log(NULL, ALL_LEVEL,
			"sniffjoke is running and INACTIVE: use \"sniffjoke start\" command or http://127.0.0.1:%d/sniffjoke.html\n",
			sjconf->running->web_bind_port
		);
	}

	next_web_poll = time(NULL) + 1;

	/* main block */
	while(1) {
		mitm->network_io();
		mitm->queue_flush();

		if(mitm->networkdown_condition == true && sjconf->running->sj_run == true) {
			internal_log(NULL, ALL_LEVEL, "Network is down, interrupting sniffjoke");
			sjconf->running->sj_run = false;
			restart_on_restore = true;
		}

		if(mitm->networkdown_condition == false && restart_on_restore == true) {
			internal_log(NULL, ALL_LEVEL, "Network restored, restarting sniffjoke");
			sjconf->running->sj_run = true;
			restart_on_restore = false;
		}
		
		check_local_unixserv(listening_socket, sjconf);

		/*if(time(NULL) >= next_web_poll) 
		{
			webio->web_poll();

			next_web_poll = time(NULL) + 1;
		}*/
	}
	/* nevah here */
}
