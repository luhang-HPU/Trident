

# Source files in this directory
set(PSI_SOURCE_FILES ${PSI_SOURCE_FILES}
    ${CMAKE_CURRENT_LIST_DIR}/crypto_util.c
    ${CMAKE_CURRENT_LIST_DIR}/eccp2_core.c
    ${CMAKE_CURRENT_LIST_DIR}/eccp2_no_endo.c
    ${CMAKE_CURRENT_LIST_DIR}/eccp2.c
    ${CMAKE_CURRENT_LIST_DIR}/hash_to_curve.c
    ${CMAKE_CURRENT_LIST_DIR}/random.c
    PARENT_SCOPE
)

if(APSI_FOURQ_AMD64)
    add_subdirectory(amd64)
elseif(APSI_FOURQ_ARM64)
    add_subdirectory(arm64)
else()
    add_subdirectory(generic)
endif()


