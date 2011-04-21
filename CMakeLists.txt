CMAKE_MINIMUM_REQUIRED(VERSION 2.4)

SET( PREFIX "/usr/local")
SET( VERSION_MAJOR 0 )
SET( VERSION_MINOR 4 )
SET( SUFFIX "-beta5" )

PROJECT(SniffJoke)
CONFIGURE_FILE( ${CMAKE_SOURCE_DIR}/src/config.h.in ${CMAKE_SOURCE_DIR}/src/config.h )
INCLUDE_DIRECTORIES(src src/service)

SET(CMAKE_SHARED_LIBRARY_PREFIX "")
ADD_SUBDIRECTORY(src)

# installation of the library require some different usate, 
# maybe I'm not implementing very well, but I'm learning cmake in this moment

INSTALL(FILES Linux-build/src/plugins/fake_seq/libfake_seq.so DESTINATION lib/sniffjoke/)
INSTALL(FILES Linux-build/src/plugins/fake_syn/libfake_syn.so DESTINATION lib/sniffjoke/)
INSTALL(FILES Linux-build/src/plugins/fake_data/libfake_data.so DESTINATION lib/sniffjoke/)
INSTALL(FILES Linux-build/src/plugins/shift_ack/libshift_ack.so DESTINATION lib/sniffjoke/)
INSTALL(FILES Linux-build/src/plugins/fake_window/libfake_window.so DESTINATION lib/sniffjoke/)
INSTALL(FILES Linux-build/src/plugins/segmentation/libsegmentation.so DESTINATION lib/sniffjoke/)
INSTALL(FILES Linux-build/src/plugins/fragmentation/libfragmentation.so DESTINATION lib/sniffjoke/)
INSTALL(FILES Linux-build/src/plugins/fake_close_fin/libfake_close_fin.so DESTINATION lib/sniffjoke/)
INSTALL(FILES Linux-build/src/plugins/fake_close_rst/libfake_close_rst.so DESTINATION lib/sniffjoke/)
INSTALL(FILES Linux-build/src/plugins/overlap_packet/liboverlap_packet.so DESTINATION lib/sniffjoke/)
INSTALL(FILES Linux-build/src/plugins/HDRoptions_probe/libHDRoptions_probe.so DESTINATION lib/sniffjoke/)
INSTALL(FILES Linux-build/src/plugins/valid_rst_fake_seq/libvalid_rst_fake_seq.so DESTINATION lib/sniffjoke/)

# installation of default configuration
INSTALL(DIRECTORY conf/generic DESTINATION var/sniffjoke)
