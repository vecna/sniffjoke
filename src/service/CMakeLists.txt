INCLUDE (CheckLibraryExists)
CHECK_INCLUDE_FILES(malloc.h HAVE_MALLOC_H)
CHECK_INCLUDE_FILES("sys/param.h;sys/mount.h" HAVE_SYS_MOUNT_H)
CONFIGURE_FILE(${CMAKE_CURRENT_SOURCE_DIR}/config.h.in ${CMAKE_CURRENT_BINARY_DIR}/config.h)

SET (CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -ldl")
ADD_EXECUTABLE(sniffjoke HDRoptions IPList IPTCPoptApply main NetIO Packet PacketFilter PacketQueue Plugin PluginPool PortConf Process SessionTrack SniffJoke TCPTrack TTLFocus UserConf Utils Debug)


# install(TARGETS sniffjoke DESTINATION ${INSTALL_BIN_DIR})
# install(TARGETS sniffjoke DESTINATION ${BIN_DIR})
# 
# -- WRONG install code
#
# CMake Error: Error in cmake code at
# /home/[...]/sniffjoke/src/service/CMakeLists.txt:10:
# INSTALL TARGETS given no DESTINATION!
# Current CMake stack: 
# [1] /home/[...]/sniffjoke/src/service/CMakeLists.txt
# -- Configuring done

