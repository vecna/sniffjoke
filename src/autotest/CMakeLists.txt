# this cause autotest to know exactly, like the compiled binary 
# through config.h, which are the configured path

SET(SJAPATH "../src/autotest")
SET(CONFIG_H "../src/service/config.h")
# EXEC_PROGRAM is executed from build/ directory, for this reason the relative paths

SET(EXTRACT_define "${SJAPATH}/__extract_line.sh")
# this command extract the single define and format them

EXEC_PROGRAM("cat ${SJAPATH}/sniffjoke-autotest.start > ${SJAPATH}/sniffjoke-autotest")
# warning: these patten inside '' are choosed to return only one line __extract_line.sh
EXEC_PROGRAM("${EXTRACT_define} ' PREFIX '  ${CONFIG_H} ${SJAPATH}/sniffjoke-autotest")
EXEC_PROGRAM("${EXTRACT_define} '_STATEDIR' ${CONFIG_H} ${SJAPATH}/sniffjoke-autotest")
EXEC_PROGRAM("${EXTRACT_define} '_LIBDIR'   ${CONFIG_H} ${SJAPATH}/sniffjoke-autotest")
EXEC_PROGRAM("${EXTRACT_define} '_BINDIR'   ${CONFIG_H} ${SJAPATH}/sniffjoke-autotest")
EXEC_PROGRAM("cat ${SJAPATH}/sniffjoke-autotest.incomplete >> ${SJAPATH}/sniffjoke-autotest")

INSTALL(FILES sniffjoke-autotest
        DESTINATION ${CMAKE_INSTALL_PREFIX}/bin
        PERMISSIONS OWNER_EXECUTE OWNER_READ GROUP_READ WORLD_READ)

INSTALL(FILES sj-iptcpopt-probe
        DESTINATION ${CMAKE_INSTALL_PREFIX}/bin
        PERMISSIONS OWNER_EXECUTE OWNER_READ GROUP_READ WORLD_READ)

INSTALL(FILES sj-commit-results
        DESTINATION ${CMAKE_INSTALL_PREFIX}/bin
        PERMISSIONS OWNER_EXECUTE OWNER_READ GROUP_READ WORLD_READ)
