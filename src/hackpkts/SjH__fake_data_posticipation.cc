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

/* 
 * SjH__fake_data_anticipation and SjH__fake_data_posticipation
 * are both the same hack, and need to be used together, anyway for 
 * design pourpose, every injected packet require a dedicated 
 * function.
 */
#include "sj_hackpkts.h"
SjH__fake_data_posticipation::SjH__fake_data_posticipation(const Packet pkt) : HackPacket(pkt) {
	debug_info = (char *)"fake data posticipation";
	prejudge = PRESCRIPTION;
	position = POSTICIPATION;
	hack_frequency = 50;
}

bool SjH__fake_data_posticipation::condition(const Packet &pkt)
{
	return (pkt.payload != NULL);		
}

void SjH__fake_data_posticipation::hack()
{		
	fillRandomPayload();
}
