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
class SjH__fake_close : public HackPacket { public: SjH__fake_close(Packet& ); };
class SjH__fake_data : public HackPacket { public: SjH__fake_data(Packet& ); };
class SjH__fake_seq : public HackPacket { public: SjH__fake_seq(Packet& ); };
class SjH__shift_ack : public HackPacket { public: SjH__shift_ack(Packet& ); };
class SjH__zero_window : public HackPacket { public: SjH__zero_window(Packet& ); };
class SjH__fake_data_anticipation : public HackPacket { public: SjH__fake_data_anticipation(Packet& ); };
class SjH__fake_data_posticipation : public HackPacket { public: SjH__fake_data_posticipation(Packet& ); };
class SjH__fake_syn : public HackPacket { public: SjH__fake_syn(Packet& ); };
class SjH__valid_rst_fake_seq : public HackPacket { public: SjH__valid_rst_fake_seq(Packet& ); };
/*
 * class SjH__half_fake_syn : public HackPacket { public: SjH__half_fake_syn(Packet& ); };
 * class SjH__half_fake_ack : public HackPacket { public: SjH__half_fake_ack(Packet& ); };
*/
#endif /* SJ_HACKPKTS_H */
