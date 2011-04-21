ADD_LIBRARY(valid_rst_fake_seq SHARED valid_rst_fake_seq.cc)

INSTALL(TARGETS valid_rst_fake_seq
        DESTINATION lib/${PROJECT_NAME}
        PERMISSIONS OWNER_READ GROUP_READ WORLD_READ)
