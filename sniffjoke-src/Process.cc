#include "sniffjoke.h"
#include <cerrno>
#include <cstdlib>
#include <cstdio>
#include <getopt.h>
#include <unistd.h>
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

	printf("%s failure %d e lock di di %s pid %d ppid %d\n", 
			__func__, failure, lockfname,getpid(), getppid());

	if (fcntl(fd, F_SETLK, &fl) == 0)
		return true;
	else {
		// handle error properly
		printf(" errorre in fcntl a %s : %d %s\n", __func__, errno, strerror(errno));
		failure = true;
		return false;
	}
}

pid_t Process::CheckLockExist(const char *lockfname) 
{
	int fd;
	struct flock fl;
	pid_t ret;

	if ((fd = open(lockfname, O_RDWR|O_CREAT)) == -1) {
		printf("%s _ fallisce l'open verso %s \n", __func__, lockfname);
		/* ERROR msg */
		failure = true;
	}

	memset(&fl, 0x00, sizeof(fl));

	if (fcntl(fd, F_GETLK, &fl) != 0) {
		printf("%s : FAIL lock GET %s per %d+%s\n", __func__, lockfname, errno, strerror(errno));
		// failure = true;
		// error handled properly 
	}
	printf("%s failure %d e lock di di %s pid %d ppid %d\n", 
			__func__, failure, lockfname,getpid(), getppid());

	printf("la struttura è: type %d when %d start %d len %d pid %d\n",
			fl.l_type, fl.l_whence, fl.l_start, fl.l_len, fl.l_pid);

	/* if the pid is present, lock is present too */
	if (fl.l_type != 0) {
		ret = readPidfile(SJ_SERVICE_CHILD_PID_FILE);
		printf(" LOCK!, pidfile %s: %d\n", SJ_SERVICE_CHILD_PID_FILE, ret);
		return ret;
	} 
	else {
		printf(" no present lock at %s\n", lockfname);
	}

	return 0;
}

void Process::processDetach() 
{
	// assert(ProcessType == Process::SJ_PROCESS_UNASSIGNED);
	pid_t pidval;

	if ((pidval = fork()) == -1) {
		failure = true;
		// error handling
		return;
	}
	printf(" xxx --- sono in %s %d e %d e il mio ppid è %d\n", __func__, pidval, getpid(), getppid());

	// Sniffjoke SERVICE FATHER: the sleeping root process for restore the network
	if (pidval) { 
		int deadtrace;
		printf(" qui faro' la waitpid di --> %d e il mio pid è %d e il mio ppid è %d\n", pidval, getpid(), getppid());
		ProcessType = SJ_PROCESS_SERVICE_FATHER; 
		writePidfile(SJ_SERVICE_FATHER_PID_FILE, pidval);

		// FIXME - decidere
		// logstream = NULL;

		/* waitpid wait until the userprocess - child pid, run */
		waitpid(-1, &deadtrace, 0);

		if (WIFEXITED(deadtrace))
			printf("WIFEXITED ganga!\n");
		if (WIFSIGNALED(deadtrace))
			printf("WIFSIGNALED gaa\n");
		if (WIFSTOPPED(deadtrace))
			printf("baaaa WIFSTOPPED\n");

		/* whenever the child die, the father restore the network */
		Process::CleanExit(true);
	} 
	// Sniffjoke SERVICE CHILD: I/O, user privileges, networking  process
	else { 
		printf(" service child! sono in %d e %d e il mio ppid è %d\n", pidval, getpid(), getppid());
		int retval = getpid();
		ReleaseLock(SJ_SERVICE_LOCK);

		processIsolation();
		ProcessType = SJ_PROCESS_SERVICE_CHILD; 
		writePidfile(SJ_SERVICE_CHILD_PID_FILE, retval);
	}
	printf("epilogo di detach per pid %d ppid %d\n", getpid(), getppid());
}

void Process::ReleaseLock(const char *lockpath) 
{
	unlink(lockpath);
	printf("%s failure %d e release di %s pid %d ppid %d\n", 
			__func__, failure, lockpath,getpid(), getppid());
}

void Process::Jail(const char *chroot_dir, struct sj_config *running) 
{

	mkdir(chroot_dir, 700);

	printf("Check dei perm: %s:\n", __func__);
	if (running->user == NULL) 
		running->user = static_cast<const char *>("nobody"); 
	if (running->group == NULL)
		running->group = static_cast<const char *>("nogroup");

	userinfo = getpwnam(running->user);
	groupinfo = getgrnam(running->group);

	printf("in %s -- user %s group %s, uid %d gid %d gr-gid %d\n", __func__, running->user, running->group,userinfo->pw_uid, userinfo->pw_gid, groupinfo->gr_gid);

	if (chdir(chroot_dir) || chroot(chroot_dir)) {
		// handle error
		failure = true;
		printf("errore non riportato - male !! %s\n", chroot_dir);
		internal_log(stderr, ALL_LEVEL, "chroot into %s: %s: unable to start sniffjoke", chroot_dir, strerror(errno));
		CleanExit(true);
	}
	printf("%s failure %d e chroot in %s pid %d ppid %d\n", 
			__func__, failure, chroot_dir,getpid(), getppid());
}

void Process::PrivilegesDowngrade(struct sj_config *running)
{

	printf("in %s -- user %s group %s, uid %d gid %d gr-gid %d\n", __func__, running->user, running->group,userinfo->pw_uid, userinfo->pw_gid, groupinfo->gr_gid);

	if (userinfo == NULL || groupinfo == NULL) {
		internal_log(NULL, ALL_LEVEL, "invalid user or group specified: %s, %s", running->user, running->group);
		failure = true;
	}

	/* if groupinfo && userinfo != null .. FIXME */
	if (groupinfo == NULL) { printf("ERRORACCIO!!!\n"); exit(0); }
	if (userinfo == NULL) { printf("ERRORACCIO2!!!\n"); exit(0); }

	if (setgid(groupinfo->gr_gid) || setuid(userinfo->pw_uid)) {
		internal_log(stderr, ALL_LEVEL, "error loosing root privileges: unable to start sniffjoke");
		CleanExit(true);
	}
	printf("%s failure %d e set in %d pid %d ppid, uid %d gid %d\n", 
			__func__, failure, getpid(), getppid(), userinfo->pw_uid, groupinfo->gr_gid);
}

void Process::CleanExit(bool boh) {
	CleanExit();
}

void Process::CleanExit(void) 
{
	int sj_srv_child_pid_FIXME = -1; // FIXME - unificare getpid con lock + estendere lock ai due processi
	switch(ProcessType) {
		case Process::SJ_PROCESS_SERVICE_FATHER:
			internal_log(stdout, VERBOSE_LEVEL, "sniffjoke server father (pid %d) is exiting", getpid());
			if (sj_srv_child_pid_FIXME != -1) {
				internal_log(stdout, VERBOSE_LEVEL, "sniffjoke server father generated a child possibily still alive, and now is killing him");
				kill(sj_srv_child_pid_FIXME, SIGTERM);
				/* let the child express his last desire */
				waitpid(sj_srv_child_pid_FIXME, NULL, 0);
			}
		
			Process::ReleaseLock(SJ_SERVICE_LOCK);  
			break;

		case Process::SJ_PROCESS_SERVICE_CHILD:
			internal_log(stdout, VERBOSE_LEVEL, "sniffjoke service child is exiting");
			unlink(SJ_SERVICE_UNIXSOCK);
			break;

		case Process::SJ_PROCESS_CLIENT:
			unlink(SJ_CLIENT_UNIXSOCK);
			break;

		case Process::SJ_PROCESS_UNASSIGNED:
		default:
			break;
	}

/*
	if (sjconf != NULL)
		delete sjconf;

	if (mitm != NULL)
		delete mitm;
*/
	printf("forced quit %s:%d\n", __FILE__, __LINE__);

	if (1) // FIXME ...
		exit(1);
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
	failure = false;
	int ret = CheckLockExist(SJ_SERVICE_LOCK);
	if (failure == true) {
		// handle error
	}
	printf("%s failure %d e ret: %d lock %s\n", __func__, failure, ret, SJ_SERVICE_LOCK);
	return ret;
}

int Process::isClientRunning(void) 
{
	int ret = CheckLockExist(SJ_CLIENT_LOCK);
	if (failure == true) {
		// handle error
	}
	printf("%s failure %d e ret: %d lock %s\n", __func__, failure, ret, SJ_CLIENT_LOCK);
	return ret;
}

pid_t Process::readPidfile(const char *pidfile) {
	int ret = 0;
	FILE *pidf = fopen(pidfile, "r");

	if (pidf != NULL) { // FIXME - better error handling
		char tmpstr[10];
		if (fgets(tmpstr, 100, pidf) != NULL)
			ret = atoi(tmpstr);
		fclose(pidf);
	}

	printf("%s: of %s from pid %d ret val %d\n", __func__, pidfile, getpid(), ret);
	return ret;
}

void Process::writePidfile(const char *pidfile, pid_t pid) {
	FILE *pidf = fopen(pidfile, "w+");

	if (pidf != NULL) { // FIXME 
		fprintf(pidf, "%d", pid);
		fclose(pidf);
	}
}

void Process::SjBackground() 
{
	printf("%s the pid %d uid %d is going to bg\n", __func__, getpid(), getuid());
	int i;
	if (fork())
		exit(0);

#if 0
	for (i = getdtablesize(); i >= 0; --i)
		close(i);

	i=open("/dev/null",O_RDWR);	 /* stdin  */
	dup(i);						 /* stdout */
	dup(i);						 /* stderr */
#endif // debug only
	internal_log(NULL, DEBUG_LEVEL, "%s DONE!!\n", __func__);
	
}

void Process::processIsolation() {

	printf("the pid %d is going to setsid \n", getpid());
	if (setsid()) {
		// failure = true;
		printf("failure pid %d uid %d gid %d of setsid %s\n",getpid(), getuid(), getgid(),  strerror(errno));
	}
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
	printf("destruction of ~Process\n");
}
