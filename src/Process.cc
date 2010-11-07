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

	/* the pidfile is opened here because otherwise doesn't contains the correct PID, 
	 * and this is the last segment of root code that should open in /var/run/sniffjoke.pid */
	Process::openPidfile();

	if ((pid_child = fork()) == -1) {
		internal_log(NULL, ALL_LEVEL, "unable to fork (calling pid %d, parent %d)", getpid(), getppid());
		raise(SIGTERM);
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

		internal_log(NULL, DEBUG_LEVEL, "child %d die, sending sigterm to %d", pid_child, getpid());
		/* whenever the child die, the father restore the network via signal handling */
		raise(SIGTERM);
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
	internal_log(NULL, DEBUG_LEVEL, "forked process continue sniffjoke running, pid %d", getpid());
}

void Process::jail() 
{
	if(chroot_dir == NULL) {
                internal_log(stderr, ALL_LEVEL, "jail() invoked but no chroot_dir specified: %s: unable to start sniffjoke");
                raise(SIGTERM);
	}

	mkdir(chroot_dir, 0700);

	if (chown(chroot_dir, userinfo->pw_uid, groupinfo->gr_gid)) {
                internal_log(stderr, ALL_LEVEL, "chown of %s to %s:%s failed: %s: unable to start sniffjoke", chroot_dir, user, group, strerror(errno));
		raise(SIGTERM);
	}

	if (chdir(chroot_dir) || chroot(chroot_dir)) {
		internal_log(stderr, ALL_LEVEL, "chroot into %s: %s: unable to start sniffjoke", chroot_dir, strerror(errno));
		raise(SIGTERM);
	}

	internal_log(NULL, VERBOSE_LEVEL, "chroot'ed process %d in %s", getpid(), chroot_dir);
}

void Process::privilegesDowngrade()
{
	if (setgid(groupinfo->gr_gid) || setuid(userinfo->pw_uid)) {
		internal_log(stderr, ALL_LEVEL, "error loosing root privileges: unable to start sniffjoke");
		raise(SIGTERM);
	}

	internal_log(NULL, VERBOSE_LEVEL, "process %d downgrade privileges to uid %d gid %d", 
		getpid(), userinfo->pw_uid, groupinfo->gr_gid);
}

/* these Servece*Closed routines are called by a runtime execution or from the 
 * signal handler, the objects are been already deleted - for this reason 
 * internal_log is not called */
void Process::serviceFatherClose() 
{
	kill(tracked_child_pid, SIGTERM); // FIXME - tracked_child_pid is not correct
	/* let the child express his last desire */
	waitpid(tracked_child_pid, NULL, WUNTRACED);
}

void Process::serviceChildClose() {
	/* ServiceChildClose can't use debugging line because the instance object could be already deleted */
	exit(0);
}

void Process::sigtrapSetup(sig_t sigtrap_function)
{
	struct sigaction ignore;

	sigemptyset(&sig_nset);
	sigaddset(&sig_nset, SIGINT);
	sigaddset(&sig_nset, SIGABRT);
	sigaddset(&sig_nset, SIGTERM);
	sigaddset(&sig_nset, SIGQUIT);
	sigaddset(&sig_nset, SIGCHLD);
	
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

void Process::unlinkPidfile(void) 
{
	FILE *pidf = fopen(SJ_PIDFILE, "r");

	if (pidf == NULL) {
		internal_log(NULL, ALL_LEVEL, "warning: requested unlink of %s seems impossibile: %s", SJ_PIDFILE, strerror(errno));
	}
	fclose(pidf);
	if(unlink(SJ_PIDFILE)) {
		internal_log(NULL, ALL_LEVEL, "unable to unlink %s: %s", SJ_PIDFILE, strerror(errno));
	}
}

pid_t Process::readPidfile(void)
{
	int ret = 0;
	FILE *pidf = fopen(SJ_PIDFILE, "r");

	if (pidf != NULL) { 
		char tmpstr[10];
		if (fgets(tmpstr, 100, pidf) != NULL)
			ret = atoi(tmpstr);
		fclose(pidf);
	} else {
		internal_log(NULL, DEBUG_LEVEL, "pidfile %s not present: %s", SJ_PIDFILE, strerror(errno));
	}

	return ret;
}

/* the root-father open the pidfile, anche the child write on them */
void Process::openPidfile(void) {

	if((pidFile = fopen(SJ_PIDFILE, "w+")) == NULL) 
		internal_log(NULL, ALL_LEVEL, "unpleasent error: unable to open pidfile %s for pid %d", SJ_PIDFILE, getpid());
}

void Process::writePidfile(void)
{
	if (pidFile != NULL) { 
		fprintf(pidFile, "%d", getpid());
		fclose(pidFile);
	}
}

void Process::background() 
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

void Process::isolation()
{
	setsid();
	umask(027);
}

/* startup of the process */
Process::Process(const char* usr, const char* grp, const char* chdir)
{
	if (getuid() || geteuid())  {
		printf("required root privileges\n");
		raise(SIGTERM);
	}

	user = usr;
	group = grp;
	chroot_dir = chdir;

	userinfo = getpwnam(user);
	groupinfo = getgrnam(group);

        if (userinfo == NULL || groupinfo == NULL) {
                internal_log(NULL, ALL_LEVEL, "invalid user or group specified: %s, %s", user, group);
                raise(SIGTERM);
        }
}
