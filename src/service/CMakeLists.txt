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

SET( PACKAGELIST EVENT )

FOREACH( PACKAGE ${PACKAGELIST} )

    FIND_PACKAGE( ${PACKAGE} REQUIRED )
    MESSAGE( "${PACKAGE}: FOUND" )
    SET( HAVE_LIB${PACKAGE} 1 )
    INCLUDE_DIRECTORIES( ${${PACKAGE}_INCLUDE_DIRS} )
    TARGET_LINK_LIBRARIES( sniffjoke ${${PACKAGE}_LIBRARY} )
    MESSAGE( STATUS "${PACKAGE} includes: ${${PACKAGE}_INCLUDE_DIRS}" )
    MESSAGE( STATUS "${PACKAGE} libs: ${${PACKAGE}_LIBRARIES}" )

ENDFOREACH(PACKAGE ${PACKAGELIST})


TARGET_LINK_LIBRARIES(sniffjoke "-ldl")

INSTALL(TARGETS sniffjoke RUNTIME DESTINATION ${CMAKE_INSTALL_PREFIX}/sbin)

