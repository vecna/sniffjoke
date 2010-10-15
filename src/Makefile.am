bin_PROGRAMS = sniffjoke

sniffjoke_SOURCES = 	DataDebug.cc \
			DataDebug.h \
			hardcoded-defines.h \
			NetIO.cc \
			NetIO.h \
			Packet.cc \
			Packet.h \
			PacketQueue.cc \
			PacketQueue.h \
			Process.cc \
			Process.h \
			SessionTrack.cc \
			SessionTrack.h \
			SniffJoke.cc \
			TCPTrack.cc \
			TCPTrack.h \
			TTLfocus.cc \
			TTLfocus.h \
			UserConf.cc \
			UserConf.h \
			Utils.h \
                    hackpkts/sj_hackpkts.h \
                    hackpkts/SjH__fake_syn.cc \
                    hackpkts/SjH__fake_close_fin.cc \
                    hackpkts/SjH__fake_close_rst.cc \
                    hackpkts/SjH__fake_data.cc \
                    hackpkts/SjH__fake_seq.cc \
                    hackpkts/SjH__shift_ack.cc \
                    hackpkts/SjH__fake_zero_window.cc \
                    hackpkts/SjH__fake_data_anticipation.cc \
                    hackpkts/SjH__fake_data_posticipation.cc \
                    hackpkts/SjH__valid_rst_fake_seq.cc

AM_CPPFLAGS = -ansi -pedantic -Wall -Werror
sniffjoke_LDFLAGS = -lrt

CLEANFILES = *~
