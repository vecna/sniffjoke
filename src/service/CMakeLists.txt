INCLUDE (CheckLibraryExists)
CHECK_INCLUDE_FILES(malloc.h HAVE_MALLOC_H)
CHECK_INCLUDE_FILES("sys/param.h;sys/mount.h" HAVE_SYS_MOUNT_H)
CONFIGURE_FILE(${CMAKE_CURRENT_SOURCE_DIR}/config.h.in ${CMAKE_CURRENT_BINARY_DIR}/config.h)

ADD_EXECUTABLE(sniffjoke HDRoptions IPList IPTCPoptApply main NetIO Packet PacketFilter PacketQueue Plugin PluginPool PortConf Process SessionTrack SniffJoke TCPTrack TTLFocus UserConf Utils Debug)

TARGET_LINK_LIBRARIES(sniffjoke "-ldl")

INSTALL(TARGETS sniffjoke RUNTIME DESTINATION /usr/local/sbin)

