SUBDIRS(src)
ADD_EXECUTABLE(sniffjoke HDRoptions.cc IPList.cc IPTCPoptApply.cc main.cc NetIO.cc Packet.cc PacketFilter.cc PacketQueue.cc Plugin.cc PluginPool.cc PortConf.cc Process.cc SessionTrack.cc SniffJoke.cc TCPTrack.cc TTLFocus.cc UserConf.cc Utils.cc)
SUBDIRS(src/client src/plugins/)
INCLUDE (CheckLibraryExists)
FIND_LIBRARY (Z z)
FIND_LIBRARY (MHASH mhash)
TARGET_LINK_LIBRARIES (sniffjoke ${MHASH} ${Z})

# FILE(GLOB_RECURSE mygui_src  src/*.cpp)
# 
# include_directories (include)
# include_directories (${Project_SOURCE_DIR}/ogrenew/OgreMain/include) #OgreMain
# include_directories (${Project_SOURCE_DIR}/ogrenew/Dependencies/include) # for freetype
# include_directories (${Project_SOURCE_DIR}/OIS-HEAD/ois/includes) #ois
# 
# # add definitions
# add_definitions("-D_USRDLL -DMYGUI_BUILD")
# 
# # the final lib
# add_library(mygui SHARED ${mygui_src})
# 
# add_dependencies(mygui OgreMain)
# target_link_libraries(mygui OgreMain)
# 
# # install target
# install(TARGETS mygui DESTINATION ${BIN_DIR})
