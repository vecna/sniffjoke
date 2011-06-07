# this cause autotest to know exactly, like the compiled binary 
# through config.h, which are the configured path

INSTALL(FILES sniffjoke-autotest
        DESTINATION ${CMAKE_INSTALL_PREFIX}/bin
        PERMISSIONS OWNER_EXECUTE OWNER_READ GROUP_READ WORLD_READ)

INSTALL(FILES sj-iptcpopt-probe
        DESTINATION ${CMAKE_INSTALL_PREFIX}/bin
        PERMISSIONS OWNER_EXECUTE OWNER_READ GROUP_READ WORLD_READ)

INSTALL(FILES sj-commit-results
        DESTINATION ${CMAKE_INSTALL_PREFIX}/bin
        PERMISSIONS OWNER_EXECUTE OWNER_READ GROUP_READ WORLD_READ)
