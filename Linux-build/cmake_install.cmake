# Install script for directory: /home/vecna/Desktop/sniffjoke-project/sniffjoke

# Set the install prefix
IF(NOT DEFINED CMAKE_INSTALL_PREFIX)
  SET(CMAKE_INSTALL_PREFIX "/usr/local")
ENDIF(NOT DEFINED CMAKE_INSTALL_PREFIX)
STRING(REGEX REPLACE "/$" "" CMAKE_INSTALL_PREFIX "${CMAKE_INSTALL_PREFIX}")

# Set the install configuration name.
IF(NOT CMAKE_INSTALL_CONFIG_NAME)
  IF(BUILD_TYPE)
    STRING(REGEX REPLACE "^[^A-Za-z0-9_]+" ""
           CMAKE_INSTALL_CONFIG_NAME "${BUILD_TYPE}")
  ELSE(BUILD_TYPE)
    SET(CMAKE_INSTALL_CONFIG_NAME "")
  ENDIF(BUILD_TYPE)
  MESSAGE(STATUS "Install configuration: \"${CMAKE_INSTALL_CONFIG_NAME}\"")
ENDIF(NOT CMAKE_INSTALL_CONFIG_NAME)

# Set the component getting installed.
IF(NOT CMAKE_INSTALL_COMPONENT)
  IF(COMPONENT)
    MESSAGE(STATUS "Install component: \"${COMPONENT}\"")
    SET(CMAKE_INSTALL_COMPONENT "${COMPONENT}")
  ELSE(COMPONENT)
    SET(CMAKE_INSTALL_COMPONENT)
  ENDIF(COMPONENT)
ENDIF(NOT CMAKE_INSTALL_COMPONENT)

# Install shared libraries without execute permission?
IF(NOT DEFINED CMAKE_INSTALL_SO_NO_EXE)
  SET(CMAKE_INSTALL_SO_NO_EXE "1")
ENDIF(NOT DEFINED CMAKE_INSTALL_SO_NO_EXE)

FILE(INSTALL DESTINATION "${CMAKE_INSTALL_PREFIX}/lib/sniffjoke" TYPE FILE FILES "/home/vecna/Desktop/sniffjoke-project/sniffjoke/Linux-build/src/plugins/fake_seq/libfake_seq.so")
FILE(INSTALL DESTINATION "${CMAKE_INSTALL_PREFIX}/lib/sniffjoke" TYPE FILE FILES "/home/vecna/Desktop/sniffjoke-project/sniffjoke/Linux-build/src/plugins/fake_syn/libfake_syn.so")
FILE(INSTALL DESTINATION "${CMAKE_INSTALL_PREFIX}/lib/sniffjoke" TYPE FILE FILES "/home/vecna/Desktop/sniffjoke-project/sniffjoke/Linux-build/src/plugins/fake_data/libfake_data.so")
FILE(INSTALL DESTINATION "${CMAKE_INSTALL_PREFIX}/lib/sniffjoke" TYPE FILE FILES "/home/vecna/Desktop/sniffjoke-project/sniffjoke/Linux-build/src/plugins/shift_ack/libshift_ack.so")
FILE(INSTALL DESTINATION "${CMAKE_INSTALL_PREFIX}/lib/sniffjoke" TYPE FILE FILES "/home/vecna/Desktop/sniffjoke-project/sniffjoke/Linux-build/src/plugins/fake_window/libfake_window.so")
FILE(INSTALL DESTINATION "${CMAKE_INSTALL_PREFIX}/lib/sniffjoke" TYPE FILE FILES "/home/vecna/Desktop/sniffjoke-project/sniffjoke/Linux-build/src/plugins/segmentation/libsegmentation.so")
FILE(INSTALL DESTINATION "${CMAKE_INSTALL_PREFIX}/lib/sniffjoke" TYPE FILE FILES "/home/vecna/Desktop/sniffjoke-project/sniffjoke/Linux-build/src/plugins/fragmentation/libfragmentation.so")
FILE(INSTALL DESTINATION "${CMAKE_INSTALL_PREFIX}/lib/sniffjoke" TYPE FILE FILES "/home/vecna/Desktop/sniffjoke-project/sniffjoke/Linux-build/src/plugins/fake_close_fin/libfake_close_fin.so")
FILE(INSTALL DESTINATION "${CMAKE_INSTALL_PREFIX}/lib/sniffjoke" TYPE FILE FILES "/home/vecna/Desktop/sniffjoke-project/sniffjoke/Linux-build/src/plugins/fake_close_rst/libfake_close_rst.so")
FILE(INSTALL DESTINATION "${CMAKE_INSTALL_PREFIX}/lib/sniffjoke" TYPE FILE FILES "/home/vecna/Desktop/sniffjoke-project/sniffjoke/Linux-build/src/plugins/overlap_packet/liboverlap_packet.so")
FILE(INSTALL DESTINATION "${CMAKE_INSTALL_PREFIX}/lib/sniffjoke" TYPE FILE FILES "/home/vecna/Desktop/sniffjoke-project/sniffjoke/Linux-build/src/plugins/HDRoptions_probe/libHDRoptions_probe.so")
FILE(INSTALL DESTINATION "${CMAKE_INSTALL_PREFIX}/lib/sniffjoke" TYPE FILE FILES "/home/vecna/Desktop/sniffjoke-project/sniffjoke/Linux-build/src/plugins/valid_rst_fake_seq/libvalid_rst_fake_seq.so")
FILE(INSTALL DESTINATION "${CMAKE_INSTALL_PREFIX}/var/sniffjoke" TYPE DIRECTORY FILES "/home/vecna/Desktop/sniffjoke-project/sniffjoke/conf/generic")
IF(NOT CMAKE_INSTALL_LOCAL_ONLY)
  # Include the install script for each subdirectory.
  INCLUDE("/home/vecna/Desktop/sniffjoke-project/sniffjoke/Linux-build/src/cmake_install.cmake")

ENDIF(NOT CMAKE_INSTALL_LOCAL_ONLY)
IF(CMAKE_INSTALL_COMPONENT)
  SET(CMAKE_INSTALL_MANIFEST "install_manifest_${CMAKE_INSTALL_COMPONENT}.txt")
ELSE(CMAKE_INSTALL_COMPONENT)
  SET(CMAKE_INSTALL_MANIFEST "install_manifest.txt")
ENDIF(CMAKE_INSTALL_COMPONENT)
FILE(WRITE "/home/vecna/Desktop/sniffjoke-project/sniffjoke/Linux-build/${CMAKE_INSTALL_MANIFEST}" "")
FOREACH(file ${CMAKE_INSTALL_MANIFEST_FILES})
  FILE(APPEND "/home/vecna/Desktop/sniffjoke-project/sniffjoke/Linux-build/${CMAKE_INSTALL_MANIFEST}" "${file}\n")
ENDFOREACH(file)
