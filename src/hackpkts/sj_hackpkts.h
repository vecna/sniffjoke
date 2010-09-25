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
#ifndef SJ_HACKPKTS_H
#define SJ_HACKPKTS_H

#include "../sj_packet.h"

class SjH__fake_close : public HackPacket {
public:
	SjH__fake_close(const Packet pkt);
	SjH__fake_close* create_hack(const Packet& pkt) { return new SjH__fake_close(pkt); };
	bool condition(const Packet&);
	void hack();
};

class SjH__fake_data : public HackPacket {
public:
	SjH__fake_data(const Packet pkt);
	SjH__fake_data* create_hack(const Packet& pkt) { return new SjH__fake_data(pkt); };
	bool condition(const Packet&);
	void hack();
};

class SjH__fake_data_anticipation : public HackPacket {
public:
	SjH__fake_data_anticipation(const Packet pkt);
	SjH__fake_data_anticipation* create_hack(const Packet& pkt) { return new SjH__fake_data_anticipation(pkt); };
	bool condition(const Packet&);
	void hack();
};

class SjH__fake_data_posticipation : public HackPacket {
public:
	SjH__fake_data_posticipation(const Packet pkt);
	SjH__fake_data_posticipation* create_hack(const Packet& pkt) { return new SjH__fake_data_posticipation(pkt); };
	bool condition(const Packet&);
	void hack();
};

class SjH__fake_seq : public HackPacket {
public:
	SjH__fake_seq(const Packet pkt);
	SjH__fake_seq* create_hack(const Packet& pkt) { return new SjH__fake_seq(pkt); };
	bool condition(const Packet&);
	void hack();
};

class SjH__shift_ack : public HackPacket {
public: 
	SjH__shift_ack(const Packet pkt);
	SjH__shift_ack* create_hack(const Packet& pkt) { return new SjH__shift_ack(pkt); };
	bool condition(const Packet&);
	void hack();
};

class SjH__valid_rst_fake_seq : public HackPacket {
public:
	SjH__valid_rst_fake_seq(const Packet pkt);
	SjH__valid_rst_fake_seq* create_hack(const Packet& pkt) { return new SjH__valid_rst_fake_seq(pkt); };
	void hack();
};

class SjH__zero_window : public HackPacket {
public:
	SjH__zero_window(const Packet pkt);
	SjH__zero_window* create_hack(const Packet& pkt) { return new SjH__zero_window(pkt); };
	void hack();
};
/*
 * class SjH__half_fake_syn : ...
 * class SjH__half_fake_ack : ...
*/
#endif /* SJ_HACKPKTS_H */
