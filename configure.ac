AC_INIT
AC_CONFIG_SRCDIR([src])
AC_CONFIG_HEADERS([src/config.h])

PACKAGE_VERSION=`grep SW_VERSION\  ./src/service/hardcoded-defines.h | cut -f2 -d"\"" | sed 's/ /-/g'`
AC_SUBST(PACKAGE_VERSION)

AC_PREFIX_DEFAULT(/usr/local)

AH_TEMPLATE(RUNUSER)
AH_TEMPLATE(RUNGROUP)
# for distribution package, here will be better use dedicated user/group
AC_DEFINE(RUNUSER, "nobody")
AC_DEFINE(RUNGROUP, "nogroup")

if test "$prefix" = "NONE"; then
   prefix="/usr/local"
fi
if test "$exec_prefix" = "NONE"; then
   exec_prefix=$prefix
fi

AH_TEMPLATE(INSTALL_PREFIX, [the prefix passed by configure])
AC_DEFINE_UNQUOTED(INSTALL_PREFIX, "`eval echo $prefix`")

AH_TEMPLATE(INSTALL_EXECPREFIX, [the exec_prefix passed by configure])
AC_DEFINE_UNQUOTED(INSTALL_EXECPREFIX, "`eval echo $exec_prefix`")

# this will not be useful ATM
# AH_TEMPLATE(INSTALL_SYSCONFDIR, [where can I find my sysconf file ?])
# AC_DEFINE_UNQUOTED(INSTALL_SYSCONFDIR, "`eval echo $sysconfdir/sniffjoke/`")

AH_TEMPLATE(INSTALL_STATEDIR, [where can I find my running track ?])
AC_DEFINE_UNQUOTED(INSTALL_STATEDIR, "`eval echo $localstatedir/sniffjoke/`")

AH_TEMPLATE(INSTALL_LIBDIR, [where can I find my plugins ?])
AC_DEFINE_UNQUOTED(INSTALL_LIBDIR, "`eval echo $libdir/sniffjoke/`")

AH_TEMPLATE(INSTALL_BINDIR, [where can I find the sniffjoke executable ?])
AC_DEFINE_UNQUOTED(INSTALL_BINDIR, "`eval echo $bindir`")


AM_INIT_AUTOMAKE(sniffjoke,$PACKAGE_VERSION)


AC_PROG_CXX
AC_LANG([C++])
AC_PROG_INSTALL

AC_DISABLE_STATIC
AC_LIBTOOL_WIN32_DLL
AC_LIBTOOL_DLOPEN
AM_PROG_LIBTOOL
AC_SEARCH_LIBS(dlopen,c dl,,)
AC_SEARCH_LIBS(lt_dlopen,c dl ltdl,,ac_ec_lt_dlopen=no)
AC_LIB_LTDL

AC_CHECK_HEADERS(algorithm,,exit 1)
AC_CHECK_HEADERS(cerrno,,exit 1)
AC_CHECK_HEADERS(csignal,,exit 1)
AC_CHECK_HEADERS(cstdarg,,exit 1)
AC_CHECK_HEADERS(cstdio,,exit 1)
AC_CHECK_HEADERS(cstdlib,,exit 1)
AC_CHECK_HEADERS(cstring,,exit 1)
AC_CHECK_HEADERS(ctime,,exit 1)
AC_CHECK_HEADERS(cctype,,exit 1)
AC_CHECK_HEADERS(map,,exit 1)
AC_CHECK_HEADERS(memory,,exit 1)
AC_CHECK_HEADERS(sstream,,exit 1)
AC_CHECK_HEADERS(stdexcept,,exit 1)
AC_CHECK_HEADERS(vector,,exit 1)
AC_CHECK_HEADERS(dlfcn.h,,exit 1)
AC_CHECK_HEADERS(fcntl.h,,exit 1)
AC_CHECK_HEADERS(getopt.h,,exit 1)
AC_CHECK_HEADERS(grp.h,,exit 1)
AC_CHECK_HEADERS(poll.h,,exit 1)
AC_CHECK_HEADERS(pwd.h,,exit 1)
AC_CHECK_HEADERS(stdint.h,,exit 1)
AC_CHECK_HEADERS(string.h,,exit 1)
AC_CHECK_HEADERS(unistd.h,,exit 1)
AC_CHECK_HEADERS(wait.h,,exit 1)
AC_CHECK_HEADERS(arpa/inet.h,,exit 1)
AC_CHECK_HEADERS(linux/if_tun.h,,exit 1)
AC_CHECK_HEADERS(net/ethernet.h,,exit 1)
AC_CHECK_HEADERS(net/if.h,,exit 1)
AC_CHECK_HEADERS(netinet/ip.h,,exit 1)
AC_CHECK_HEADERS(netinet/ip_icmp.h,,exit 1)
AC_CHECK_HEADERS(netinet/tcp.h,,exit 1)
AC_CHECK_HEADERS(netpacket/packet.h,,exit 1)
AC_CHECK_HEADERS(sys/ioctl.h,,exit 1)
AC_CHECK_HEADERS(sys/param.h,,exit 1)
AC_CHECK_HEADERS(sys/poll.h,,exit 1)
AC_CHECK_HEADERS(sys/stat.h,,exit 1)
AC_CHECK_HEADERS(sys/types.h,,exit 1)
AC_CHECK_HEADERS(sys/un.h,,exit 1)

AC_CONFIG_FILES(
		Makefile
		src/Makefile
		src/service/Makefile
		src/client/Makefile
		src/plugins/Makefile
		src/plugins/fake_close_fin/Makefile
		src/plugins/fake_close_rst/Makefile
		src/plugins/fake_data/Makefile
		src/plugins/fake_seq/Makefile
		src/plugins/fake_syn/Makefile
		src/plugins/fake_zero_window/Makefile
		src/plugins/shift_ack/Makefile
		src/plugins/valid_rst_fake_seq/Makefile
		src/plugins/fragmentation/Makefile
		src/plugins/fragmentation_with_fake_data/Makefile
)


CFLAGS="-O3 -ansi -pedantic -Wall"
CXXFLAGS="$CFLAGS"

AC_OUTPUT
