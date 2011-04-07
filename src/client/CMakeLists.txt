ADD_EXECUTABLE(sniffjokecli main SniffJokeCli)

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
