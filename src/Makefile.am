bin_PROGRAMS = sniffjoke

sniffjoke_SOURCES = sj_main.cc \
                    sj_utils.h \
                    sj_defines.h \
                    sj_conf.h \
                    sj_conf.cc \
                    sj_process.h \
                    sj_process.cc \
                    sj_netio.h \
                    sj_netio.cc \
                    sj_packet.h \
                    sj_packet.cc \
                    sj_packetqueue.h \
                    sj_packetqueue.cc \
                    sj_ttlfocus.h \
                    sj_ttlfocus.cc \
                    sj_sessiontrack.h \
                    sj_sessiontrack.cc \
                    sj_tcptrack.h \
                    sj_tcptrack.cc \
                    sj_optional_datadebug.h \
                    sj_optional_datadebug.cc \
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
