#include "SjUtils.h"
#include "Process.h"

#include "SjConf.h" /* struct sj_config */

#include <getopt.h>
#include <fcntl.h>
#include <pwd.h>
#include <grp.h>
#include <wait.h>

#include <sys/un.h>

extern int errno;

bool Process::setLocktoExist(const char *lockfname) {
	int fd;
	struct flock fl;

	if ((fd = open(lockfname, O_RDWR|O_CREAT)) == -1) {
		/* ERROR msg */
		failure = true;
	}

	memset(&fl, 0x00, sizeof(fl));
	fl.l_type   = F_WRLCK;

	if (fcntl(fd, F_SETLK, &fl) == 0) {
		internal_log(NULL, DEBUG_LEVEL, "set lock in %s", lockfname);
		return true;
	}
	else {
		int saved_errno = errno;
		internal_log(NULL, ALL_LEVEL, "unable to lock %s", lockfname);
		failure = true;
//		check_call_ret("unable to lock", saved_errno, -1, true);
	}
}

pid_t Process::CheckLockExist(const char *lockfname) 
{
	int fd;
	struct flock fl;
	pid_t ret;

	if ((fd = open(lockfname, O_RDWR|O_CREAT)) == -1) {
		int saved_errno = errno;
		internal_log(NULL, ALL_LEVEL, "unable to open lock file: %s", lockfname);
		failure = true; return -1;
//		check_call_ret("unable to open", saved_errno, -1, true);
	}

	memset(&fl, 0x00, sizeof(fl));

	if (fcntl(fd, F_GETLK, &fl) != 0) {
		int saved_errno = errno;
		internal_log(NULL, ALL_LEVEL, "unable to get lock from file: %s", lockfname);
		failure = true;
//		check_call_ret("unable to get lock", saved_errno, -1, true);
	}

	/* if the pid is present, lock is present too */
	if (fl.l_type != 0) {
		ret = readPidfile(SJ_SERVICE_CHILD_PID_FILE);
		internal_log(NULL, VERBOSE_LEVEL, "lock present in %s, pidfile %s, pid locking %d",
			lockfname, SJ_SERVICE_CHILD_PID_FILE, ret);
		return ret;
	} 
	else {
		internal_log(NULL, DEBUG_LEVEL, "lock not present in %s", lockfname);
		return 0;
	}
}

void Process::processDetach() 
{
	pid_t pidval;

	if ((pidval = fork()) == -1) {
		int saved_errno = errno;
		internal_log(NULL, ALL_LEVEL, "unable to fork (calling pid %d, parent %d)", getpid(), getppid());
		failure = true;
	}

	if (pidval) 
	{ 
		/* 
		 * Sniffjoke SERVICE FATHER: the sleeping root 
		 * process for restore the network */
		int deadtrace;
		ProcessType = SJ_PROCESS_SERVICE_FATHER; 
		writePidfile(SJ_SERVICE_FATHER_PID_FILE, getpid() );

		/* be sure that the child has runned */
		usleep(500);
		pid_t child = readPidfile(SJ_SERVICE_CHILD_PID_FILE);

		if(child <= 0) {
			internal_log(NULL, ALL_LEVEL, "child is not running, received pid %d", child);
			// FIXME - found a congruent way for closing process 
			Process::CleanExit(true);
		}

		/* waitpid wait until the userprocess - child pid, run */
		waitpid(child, &deadtrace, WUNTRACED);

		if (WIFEXITED(deadtrace))
			internal_log(NULL, VERBOSE_LEVEL, "child %d WIFEXITED", pidval);
		if (WIFSIGNALED(deadtrace))
			internal_log(NULL, VERBOSE_LEVEL, "child %d WIFSIGNALED", pidval);
		if (WIFSTOPPED(deadtrace))
			internal_log(NULL, VERBOSE_LEVEL, "child %d WIFSTOPPED", pidval);

		/* whenever the child die, the father restore the network */
		Process::CleanExit(true);
	} 
	else 
	{ 
		/* 
		 * Sniffjoke SERVICE CHILD: I/O, user privileges, 
		 * networking process */
		ReleaseLock(SJ_SERVICE_LOCK);

		processIsolation();
		ProcessType = SJ_PROCESS_SERVICE_CHILD; 
		writePidfile(SJ_SERVICE_CHILD_PID_FILE, getpid() );
	}
}

void Process::ReleaseLock(const char *lockpath) 
{
	unlink(lockpath);
	internal_log(NULL, VERBOSE_LEVEL, "unlink of lock file %s", lockpath);
}

void Process::Jail(const char *chroot_dir, struct sj_config *running) 
{
	mkdir(chroot_dir, 700);

	userinfo = getpwnam(running->user);
	groupinfo = getgrnam(running->group);

	if (chdir(chroot_dir) || chroot(chroot_dir)) {
		internal_log(stderr, ALL_LEVEL, "chroot into %s: %s: unable to start sniffjoke", chroot_dir, strerror(errno));
		failure = true;
		// check_call_ret ... 
		CleanExit(true);
	}
	internal_log(NULL, VERBOSE_LEVEL, "chroot'ed process %d in %s", getpid(), chroot_dir);
}

void Process::PrivilegesDowngrade(struct sj_config *running)
{

	if (userinfo == NULL || groupinfo == NULL) {
		internal_log(NULL, ALL_LEVEL, "invalid user or group specified: %s, %s", running->user, running->group);
		failure = true;
	}

	/* verify configuration and command line */
	// assert(groupinfo != NULL); assert(userinfo != NULL);

	if (setgid(groupinfo->gr_gid) || setuid(userinfo->pw_uid)) {
		internal_log(stderr, ALL_LEVEL, "error loosing root privileges: unable to start sniffjoke");
		CleanExit(true);
	}
	internal_log(NULL, VERBOSE_LEVEL, "process %d downgrade privileges to uid %d gid %d", userinfo->pw_uid, groupinfo->gr_gid);
}

void Process::CleanExit(bool boh) {
	CleanExit();
}

void Process::CleanExit(void) 
{
	// FIXME - getpid + lock and process tracking should and must unify unificare getpid con lock + estendere lock ai due processi
	int sj_srv_child_pid_FIXME = readPidfile(SJ_SERVICE_CHILD_PID_FILE); 

	switch(ProcessType) {
		case Process::SJ_PROCESS_SERVICE_FATHER:
			internal_log(stdout, VERBOSE_LEVEL, "sniffjoke-service father (pid %d) EXIT", getpid());
			Process::ReleaseLock(SJ_SERVICE_LOCK);  
			unlink(SJ_SERVICE_FATHER_PID_FILE);
			unlink(SJ_SERVICE_CHILD_PID_FILE);  // here because the child is chroot'ed
			if (sj_srv_child_pid_FIXME != -1) 
			{
				internal_log(stdout, VERBOSE_LEVEL, "sniffjoke-service father is killing the child");
				kill(sj_srv_child_pid_FIXME, SIGTERM);
				/* let the child express his last desire */
				waitpid(sj_srv_child_pid_FIXME, NULL, WUNTRACED);
			}
			break;

		case Process::SJ_PROCESS_SERVICE_CHILD:
			internal_log(stdout, VERBOSE_LEVEL, "sniffjoke-service child is exiting");
			Process::ReleaseLock(SJ_SERVICE_LOCK);  
			unlink(SJ_SERVICE_UNIXSOCK);
			break;

		case Process::SJ_PROCESS_CLIENT:
			unlink(SJ_CLIENT_UNIXSOCK);
			break;

		case Process::SJ_PROCESS_UNASSIGNED:
		default:
			break;
	}

	exit(0);
}

void Process::sigtrapSetup(sig_t sigtrap_function) 
{
	signal(SIGINT, sigtrap_function);
	signal(SIGABRT, sigtrap_function);
	signal(SIGTERM, sigtrap_function);
	signal(SIGQUIT, sigtrap_function);
	signal(SIGUSR1, SIG_IGN);
}

int Process::isServiceRunning(void) 
{
	return CheckLockExist(SJ_SERVICE_LOCK);
}

int Process::isClientRunning(void) 
{
	return CheckLockExist(SJ_CLIENT_LOCK);
}

pid_t Process::readPidfile(const char *pidfile) {
	int ret = 0;
	FILE *pidf = fopen(pidfile, "r");

	if (pidf != NULL) { 
		char tmpstr[10];
		if (fgets(tmpstr, 100, pidf) != NULL)
			ret = atoi(tmpstr);
		fclose(pidf);
	} else {
		internal_log(NULL, DEBUG_LEVEL, "no pidfile %s", pidfile);
	}

	return ret;
}

void Process::writePidfile(const char *pidfile, pid_t pid) {
	FILE *pidf = fopen(pidfile, "w+");

	if (pidf != NULL) { 
		fprintf(pidf, "%d", pid);
		fclose(pidf);
	} else {
		internal_log(NULL, ALL_LEVEL, "unpleasent error: unable to open pidfile %s for pid %d", pidfile, pid);
	}
}

void Process::SjBackground() 
{
	int i;

	internal_log(NULL, DEBUG_LEVEL, "the pid %d, uid %d is going background and closing std*", getpid(), getuid());
	if (fork())
		exit(0);

	for (i = getdtablesize(); i >= 0; --i)
		close(i);

	i=open("/dev/null",O_RDWR);	/* stdin  */
	dup(i);				/* stdout */
	dup(i);				/* stderr */
	
}

void Process::processIsolation() {
/* -- is failing !!?
	if (setsid()) {
		int saved_errno = errno;
		internal_log(NULL, ALL_LEVEL, "unable to setsid: %s", strerror(errno));
		failure = true;
//		check_call_ret("unable to setsid", errno, -1, true);
	}
*/
	umask(0);
}

void Process::SetProcType(sj_process_t ProcType) {
	ProcessType = ProcType;
}

	
/* startup of the process */
Process::Process(struct sj_useropt *useropt) 
{
	// logstream_ptr = &(useropt->logstream);

	if (getuid() || geteuid())  {
		printf("required root privileges\n");
		failure = true;
	}

}

Process::~Process() {
}
