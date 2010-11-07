/*
 *   SniffJoke is a software able to confuse the Internet traffic analysis,
 *   developed with the aim to improve digital privacy in communications and
 *   to show and test some securiy weakness in traffic analysis software.
 *   
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
#ifndef SJ_PROCESS_H
#define SJ_PROCESS_H

#include "hardcoded-defines.h"

#include <csignal>
#include <cstdio>

class Process {
private:

	const char* user;
	const char* group;
	const char* chroot_dir;

        struct passwd *userinfo;
        struct group *groupinfo;

	sigset_t sig_nset;
	sigset_t sig_oset;
	struct sigaction action;

	FILE *pidFile;
public:
	pid_t tracked_child_pid;
	bool failure;
	
	Process(const char* user, const char* group, const char* chroot_dir);

	pid_t readPidfile();
	void writePidfile();
	void unlinkPidfile();
	void openPidfile();

	void detach() ;
	void jail();
	void privilegesDowngrade();
	void sigtrapSetup(sig_t sigtrap_function);
	void sigtrapEnable();
	void sigtrapDisable();
	void background();
	void isolation() ;

	void serviceFatherClose();
	void serviceChildClose();
};

#endif /* SJ_Process_H */
