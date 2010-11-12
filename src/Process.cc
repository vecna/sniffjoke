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

#include <fcntl.h>
#include <getopt.h>
#include <grp.h>
#include <pwd.h>
#include <wait.h>

int Process::detach() 
{
	pid_t pid_child;
	int pdes[2];
	pipe(pdes);

	if ((pid_child = fork()) == -1) {
		debug.log(ALL_LEVEL, "detach(): unable to fork (calling pid %d, parent %d)", getpid(), getppid());
		SJ_RUNTIME_EXCEPTION();	
	}
	
	if (pid_child)
	{ 
		/* 
		 * Sniffjoke SERVICE FATHER: root privileges
		 * process delegated to network cleanhup
		 */
		 
		/* from now on there is no need of files in the root, so we can chroot 
		 * into the same directory where the child will chroot.
		 * this is also important becose in this way the root process can access
		 * to the unix socket of the child, for example to request it's 'quit' */
		 
		close(pdes[1]);
	        read(pdes[0], &pid_child, sizeof(pid_t));
		close(pdes[0]);
		
		return pid_child;

	} else 	{
		/* 
		 * Sniffjoke SERVICE CHILD: I/O, user privileges
		 * networking process
		 */

		isolation();
		
		pid_child = getpid();

		close(pdes[0]);
        	write(pdes[1], &pid_child, sizeof(pid_t)); 
		close(pdes[1]);
		
		debug.log(DEBUG_LEVEL, "detach(): forked child process, pid %d", getpid());
		
		return 0;
	}
}

void Process::jail() 
{

	userconf.running.chrooted = false;

	if(userconf.running.chroot_dir == NULL) {
                debug.log(ALL_LEVEL, "jail() invoked but no chroot_dir specified: %s: unable to start sniffjoke");
		SJ_RUNTIME_EXCEPTION();
	}

	mkdir(userconf.running.chroot_dir, 0700);

	if (chown(userconf.running.chroot_dir, userinfo.pw_uid, groupinfo.gr_gid)) {
                debug.log(ALL_LEVEL, "jail(): chown of %s to %s:%s failed: %s: unable to start sniffjoke",
			userconf.running.chroot_dir, userconf.running.user, userconf.running.group, strerror(errno));
		SJ_RUNTIME_EXCEPTION();
	}

	if (chdir(userconf.running.chroot_dir) || chroot(userconf.running.chroot_dir)) {
		debug.log(ALL_LEVEL, "jail(): chroot into %s: %s: unable to start sniffjoke", userconf.running.chroot_dir, strerror(errno));
		SJ_RUNTIME_EXCEPTION();
	}

	userconf.running.chrooted = true;

	debug.log(VERBOSE_LEVEL, "jail(): chroot'ed process %d in %s", getpid(), userconf.running.chroot_dir);
}

void Process::privilegesDowngrade()
{
	if (setgid(groupinfo.gr_gid) || setuid(userinfo.pw_uid)) {
		debug.log(ALL_LEVEL, "privilegesDowngrade(): error loosing root privileges");
		SJ_RUNTIME_EXCEPTION();
	}

	debug.log(VERBOSE_LEVEL, "privilegesDowngrade(): process %d downgrade privileges to uid %d gid %d", 
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
		debug.log(DEBUG_LEVEL, "readPidfile(): pidfile %s not present: %s", SJ_PIDFILE, strerror(errno));
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
                debug.log(ALL_LEVEL, "writePidfile(): unable to open pidfile %s for pid %d for writing", SJ_PIDFILE, getpid());
                SJ_RUNTIME_EXCEPTION();
        }

	fprintf(pidFile, "%d", getpid());
	fclose(pidFile);
}

void Process::unlinkPidfile(void) 
{
	FILE *pidFile = fopen(SJ_PIDFILE, "r");

	if (pidFile == NULL) {
		debug.log(ALL_LEVEL, "unlinkPidfile(): requested unlink of %s seems impossibile: %s", SJ_PIDFILE, strerror(errno));
		SJ_RUNTIME_EXCEPTION();
	}
	fclose(pidFile);
	if(unlink(SJ_PIDFILE)) {
		debug.log(ALL_LEVEL, "unlinkPidfile(): unable to unlink %s: %s", SJ_PIDFILE, strerror(errno));
		SJ_RUNTIME_EXCEPTION();
	}
}


void Process::background() 
{
	int i;

	debug.log(DEBUG_LEVEL, "background(): the pid %d, uid %d is going background and closing std*", getpid(), getuid());
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
Process::Process(UserConf &conf) :
	userconf(conf),
	userinfo_buf(NULL),
	groupinfo_buf(NULL)
{
	debug.log(ALL_LEVEL, "Process()");

	if (getuid() || geteuid())  {
		debug.log(ALL_LEVEL, "Process(): required root privileges");
		SJ_RUNTIME_EXCEPTION();
	}

        struct passwd *userinfo_result;
        struct group *groupinfo_result;

	size_t userinfo_buf_len = sysconf(_SC_GETPW_R_SIZE_MAX);
	size_t groupinfo_buf_len = sysconf(_SC_GETGR_R_SIZE_MAX);

	userinfo_buf = calloc(1, userinfo_buf_len);
	groupinfo_buf = calloc(1, groupinfo_buf_len);

	if(userinfo_buf == NULL || groupinfo_buf == NULL) {
                debug.log(ALL_LEVEL, "Process(): problem in memory allocation for userinfo or groupinfo");
                SJ_RUNTIME_EXCEPTION();
	}

        getpwnam_r(userconf.running.user, &userinfo, (char*)userinfo_buf, userinfo_buf_len, &userinfo_result);
	getgrnam_r(userconf.running.group, &groupinfo, (char*)groupinfo_buf, groupinfo_buf_len, &groupinfo_result);

        if (userinfo_result == NULL || groupinfo_result == NULL) {
                debug.log(ALL_LEVEL, "Process(): invalid user or group specified: %s, %s", userconf.running.user, userconf.running.group);
		SJ_RUNTIME_EXCEPTION();
        }
}

Process::~Process()
{
	free(userinfo_buf);
	free(groupinfo_buf);
	debug.log(ALL_LEVEL, "~Process()");
}
