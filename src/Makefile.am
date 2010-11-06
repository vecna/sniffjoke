bin_PROGRAMS =		sniffjoke

sniffjoke_SOURCES =	hardcoded-defines.h \
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
			Utils.h

AM_CPPFLAGS =		-ansi -pedantic -Wall
sniffjoke_LDFLAGS =	-lrt -Wl,-export-dynamic

CLEANFILES =		.deps/ \
			.libs/ \
			config.h \
			config.h.in \
			stamp-h1 \
			Makefile.in
