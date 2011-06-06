CMAKE_MINIMUM_REQUIRED( VERSION 2.4 )

PROJECT( sniffjoke )

SET( PREFIX "/usr/local" )
SET( VERSION_MAJOR 0 )
SET( VERSION_MINOR 4 )
SET( SUFFIX "-1" )

SET(CMAKE_SHARED_LIBRARY_PREFIX "")
# SET(CMAKE_CXX_FLAGS "-g3 -O3 -ansi -pedantic -Wall -Wno-variadic-macros ${CMAKE_CXX_FLAGS}")
SET(CMAKE_CXX_FLAGS "-O3 -ansi -pedantic -Wall -Wno-variadic-macros ${CMAKE_CXX_FLAGS}")

INCLUDE_DIRECTORIES( src src/service )

ADD_SUBDIRECTORY( src )
ADD_SUBDIRECTORY( conf )

if( MANDIR )
    set( PATH_MAN ${MANDIR} )
else( MANDIR )
    find_path( PATH_MAN NAMES "man" PATHS ${SEARCH_SYS} NO_DEFAULT_PATH )
    if( PATH_MAN )
        set( PATH_MAN "${PATH_MAN}/man/man1" )
    else( PATH_MAN )
        set( PATH_MAN "${CMAKE_INSTALL_PREFIX}/share/man/man1" )
    endif( PATH_MAN )
endif( MANDIR )

INSTALL(FILES doc/sniffjoke.1 doc/sniffjokectl.1 doc/sniffjoke-autotest.1
        DESTINATION ${PATH_MAN}
        PERMISSIONS OWNER_READ OWNER_WRITE GROUP_READ WORLD_READ)

# uninstall target as officially explained on:
#   - http://www.youtube.com/watch?v=fw-nJRD78tA
#   - http://www.cmake.org/Wiki/CMake_FAQ#Can_I_do_.22make_uninstall.22_with_CMake.3F
CONFIGURE_FILE(
    "${CMAKE_CURRENT_SOURCE_DIR}/cmake_uninstall.cmake.in"
    "${CMAKE_CURRENT_BINARY_DIR}/cmake_uninstall.cmake"
    IMMEDIATE @ONLY
)

ADD_CUSTOM_TARGET(
    uninstall
    COMMAND ${CMAKE_COMMAND} -P ${CMAKE_CURRENT_BINARY_DIR}/cmake_uninstall.cmake
)
# end of uninstall target
