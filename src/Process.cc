/*
 *   SniffJoke is a software able to confuse the Internet traffic analysis,
 *   developed with the aim to improve digital privacy in communications and
 *   to show and test some securiy weakness in traffic analysis software.
    
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
#include "Process.h"
#include "UserConf.h"
#include "Utils.h"

#include <fcntl.h>
#include <getopt.h>
#include <grp.h>
#include <pwd.h>
#include <wait.h>
#include <sys/un.h>

void Process::detach() 
{
	pid_t pid, pid_child;
	int pdes[2];
	pipe(pdes);

	if ((pid_child = fork()) == -1) {
		internal_log(NULL, ALL_LEVEL, "detach(): unable to fork (calling pid %d, parent %d)", getpid(), getppid());
		SJ_RUNTIME_EXCEPTION();	
	}

	if (pid_child)
	{ 
		/* 
		 * Sniffjoke SERVICE FATHER: the sleeping root 
		 * process for restore the network
		 */
		int deadtrace;
		pid = getpid();

		close(pdes[1]);
	        read(pdes[0], &pid_child, sizeof(pid_t));
		close(pdes[0]);

		tracked_child_pid = pid_child;

		waitpid(pid_child, &deadtrace, WUNTRACED);

		if (WIFEXITED(deadtrace))
			internal_log(NULL, VERBOSE_LEVEL, "child %d WIFEXITED", pid_child);
		if (WIFSIGNALED(deadtrace))
			internal_log(NULL, VERBOSE_LEVEL, "child %d WIFSIGNALED", pid_child);
		if (WIFSTOPPED(deadtrace))
			internal_log(NULL, VERBOSE_LEVEL, "child %d WIFSTOPPED", pid_child);

		internal_log(NULL, DEBUG_LEVEL, "child %d died, going to shutdown", pid_child);

		exit(0);
	} 
	else 
	{
		/* 
		 * Sniffjoke SERVICE CHILD: I/O, user privileges, networking process
		 */

		/* the pidfile contains the child pid, whenever is killed, the father detect via waitpid */
		Process::writePidfile();

		isolation();
		pid = getpid();

		close(pdes[0]);
        	write(pdes[1], &pid, sizeof(pid_t)); 
		close(pdes[1]);
	}
	internal_log(NULL, DEBUG_LEVEL, "detach(): forked process continue sniffjoke running, pid %d", getpid());
}

void Process::jail() 
{

	usercfg.running.chrooted = false;

	if(usercfg.running.chroot_dir == NULL) {
                internal_log(stderr, ALL_LEVEL, "jail() invoked but no chroot_dir specified: %s: unable to start sniffjoke");
		SJ_RUNTIME_EXCEPTION();
	}

	mkdir(usercfg.running.chroot_dir, 0700);

	if (chown(usercfg.running.chroot_dir, userinfo.pw_uid, groupinfo.gr_gid)) {
                internal_log(stderr, ALL_LEVEL, "jail(): chown of %s to %s:%s failed: %s: unable to start sniffjoke",
			usercfg.running.chroot_dir, usercfg.running.user, usercfg.running.group, strerror(errno));
		SJ_RUNTIME_EXCEPTION();
	}

	if (chdir(usercfg.running.chroot_dir) || chroot(usercfg.running.chroot_dir)) {
		internal_log(stderr, ALL_LEVEL, "jail(): chroot into %s: %s: unable to start sniffjoke", usercfg.running.chroot_dir, strerror(errno));
		SJ_RUNTIME_EXCEPTION();
	}

	usercfg.running.chrooted = true;

	internal_log(NULL, VERBOSE_LEVEL, "jail(): chroot'ed process %d in %s", getpid(), usercfg.running.chroot_dir);
}

void Process::privilegesDowngrade()
{
	if (setgid(groupinfo.gr_gid) || setuid(userinfo.pw_uid)) {
		internal_log(stderr, ALL_LEVEL, "privilegesDowngrade(): error loosing root privileges");
		SJ_RUNTIME_EXCEPTION();
	}

	internal_log(NULL, VERBOSE_LEVEL, "privilegesDowngrade(): process %d downgrade privileges to uid %d gid %d", 
		getpid(), userinfo.pw_uid, groupinfo.gr_gid);
}

void Process::sigtrapSetup(sig_t sigtrap_function)
{
	struct sigaction ignore;
	memset(&ignore, 0, sizeof(struct sigaction));

	sigemptyset(&sig_nset);
	sigaddset(&sig_nset, SIGINT);
	sigaddset(&sig_nset, SIGABRT);
	sigaddset(&sig_nset, SIGTERM);
	sigaddset(&sig_nset, SIGQUIT);
	sigaddset(&sig_nset, SIGCHLD);

	memset(&action, 0, sizeof(struct sigaction));	
	action.sa_handler = sigtrap_function;
	action.sa_mask = sig_nset;
	
	ignore.sa_handler = SIG_IGN;
	
	sigaction(SIGINT, &action, NULL);
	sigaction(SIGABRT, &action, NULL);
	sigaction(SIGTERM, &action, NULL);
	sigaction(SIGQUIT, &action, NULL); 
	sigaction(SIGUSR1, &ignore, NULL);
}

void Process::sigtrapEnable()
{
	sigprocmask(SIG_SETMASK, &sig_oset, NULL); 
}

void Process::sigtrapDisable()
{
	sigemptyset(&sig_nset);
	sigaddset(&sig_nset, SIGINT);
	sigaddset(&sig_nset, SIGABRT);
	sigaddset(&sig_nset, SIGTERM);
	sigaddset(&sig_nset, SIGQUIT);
	sigprocmask(SIG_BLOCK, &sig_nset, &sig_oset);	
}

pid_t Process::readPidfile(void)
{
	int ret = 0;

        FILE *pidFile;
        if((pidFile = fopen(SJ_PIDFILE, "r")) == NULL) {
		internal_log(NULL, DEBUG_LEVEL, "readPidfile(): pidfile %s not present: %s", SJ_PIDFILE, strerror(errno));
		return ret;
	}

	char tmpstr[10];
	if (fgets(tmpstr, 100, pidFile) != NULL)
		ret = atoi(tmpstr);
	fclose(pidFile);


	return ret;
}

void Process::writePidfile(void)
{
        FILE *pidFile;
        if((pidFile = fopen(SJ_PIDFILE, "w+")) == NULL) {
                internal_log(NULL, ALL_LEVEL, "writePidfile(): unable to open pidfile %s for pid %d for writing", SJ_PIDFILE, getpid());
                SJ_RUNTIME_EXCEPTION();
        }

	fprintf(pidFile, "%d", getpid());
	fclose(pidFile);
}

void Process::unlinkPidfile(void) 
{
	FILE *pidFile = fopen(SJ_PIDFILE, "r");

	if (pidFile == NULL) {
		internal_log(NULL, ALL_LEVEL, "unlinkPidfile(): requested unlink of %s seems impossibile: %s", SJ_PIDFILE, strerror(errno));
		SJ_RUNTIME_EXCEPTION();
	}
	fclose(pidFile);
	if(unlink(SJ_PIDFILE)) {
		internal_log(NULL, ALL_LEVEL, "unlinkPidfile(): unable to unlink %s: %s", SJ_PIDFILE, strerror(errno));
		SJ_RUNTIME_EXCEPTION();
	}
}


void Process::background() 
{
	int i;

	internal_log(NULL, DEBUG_LEVEL, "background(): the pid %d, uid %d is going background and closing std*", getpid(), getuid());
	if (fork())
		exit(0);
	for (i = getdtablesize(); i >= 0; --i)
		close(i);

	i=open("/dev/null",O_RDWR);	/* stdin  */
	dup(i);				/* stdout */
	dup(i);				/* stderr */
	
}

void Process::isolation()
{
	setsid();
	umask(027);
}

/* startup of the process */
Process::Process(UserConf &userconf) :
	usercfg(userconf),
	userinfo_buf(NULL),
	groupinfo_buf(NULL)
{
	if (getuid() || geteuid())  {
		internal_log(NULL, ALL_LEVEL, "Process(): required root privileges");
		SJ_RUNTIME_EXCEPTION();
	}

        struct passwd *userinfo_result;
        struct group *groupinfo_result;

	size_t userinfo_buf_len = sysconf(_SC_GETPW_R_SIZE_MAX);
	size_t groupinfo_buf_len = sysconf(_SC_GETGR_R_SIZE_MAX);

	userinfo_buf = calloc(1, userinfo_buf_len);
	groupinfo_buf = calloc(1, groupinfo_buf_len);

	if(userinfo_buf == NULL || groupinfo_buf == NULL) {
                internal_log(NULL, ALL_LEVEL, "Process(): problem in memory allocation for userinfo or groupinfo");
                SJ_RUNTIME_EXCEPTION();
	}

        getpwnam_r(usercfg.running.user, &userinfo, (char*)userinfo_buf, userinfo_buf_len, &userinfo_result);
	getgrnam_r(usercfg.running.group, &groupinfo, (char*)groupinfo_buf, groupinfo_buf_len, &groupinfo_result);

        if (userinfo_result == NULL || groupinfo_result == NULL) {
                internal_log(NULL, ALL_LEVEL, "Process(): invalid user or group specified: %s, %s", usercfg.running.user, usercfg.running.group);
		SJ_RUNTIME_EXCEPTION();
        }
}

Process::~Process()
{
	free(userinfo_buf);
	free(groupinfo_buf);
}
