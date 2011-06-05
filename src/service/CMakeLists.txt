CONFIGURE_FILE(${CMAKE_CURRENT_SOURCE_DIR}/config.h.in ${CMAKE_CURRENT_SOURCE_DIR}/config.h)

ADD_EXECUTABLE(sniffjoke
               HDRoptions
               IPList
               IPTCPopt
               IPTCPoptImpl
               OptionPool
               main
               NetIO
               Packet
               PacketFilter
               PacketQueue
               Plugin
               PluginPool
               PortConf
               Process
               SessionTrack
               SniffJoke
               TCPTrack
               TTLFocus
               UserConf
               Utils
               Debug)

TARGET_LINK_LIBRARIES(sniffjoke "-ldl")

INSTALL(TARGETS sniffjoke RUNTIME DESTINATION ${CMAKE_INSTALL_PREFIX}/sbin)

