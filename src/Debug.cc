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

#include "Debug.h"

Debug::Debug() :
	debuglevel(ALL_LEVEL),
	logstream(NULL),
	session_logstream(NULL),
	packet_logstream(NULL)
{}

void Debug::log(uint8_t errorlevel, const char *msg, ...) 
{
	if (errorlevel <= debuglevel) { 
	
		va_list arguments;
		time_t now = time(NULL);
		FILE *output_flow;

		if (logstream != NULL)
			output_flow = logstream;
		else
			output_flow = stderr;

		if (errorlevel == PACKETS_DEBUG && packet_logstream != NULL)
			output_flow = packet_logstream;

		if (errorlevel == SESSION_DEBUG && session_logstream != NULL)
			output_flow = session_logstream;

			char time_str[sizeof("YYYY-MM-GG HH:MM:SS")];
			strftime(time_str, sizeof(time_str), "%Y-%m-%d %H:%M:%S", localtime(&now));

			va_start(arguments, msg);
			fprintf(output_flow, "%s ", time_str);
			vfprintf(output_flow, msg, arguments);
			fprintf(output_flow, "\n");
			fflush(output_flow);
			va_end(arguments);
	}
}
