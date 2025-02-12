
# Enable HTTPS functionality. This requires to link against the kritis3m_asl library!
option(ENABLE_HTTPS "Enables Certificat Verification in HTTP(S) requests" ON)

# Library Sources of kritis3m_http_libs
add_library(kritis3m-http-libs STATIC
        ${CMAKE_CURRENT_SOURCE_DIR}/src/cJSON_Utils.c
        ${CMAKE_CURRENT_SOURCE_DIR}/src/cJSON.c
        ${CMAKE_CURRENT_SOURCE_DIR}/src/http_client.c
        ${CMAKE_CURRENT_SOURCE_DIR}/src/http_parser_url.c
        ${CMAKE_CURRENT_SOURCE_DIR}/src/linux_comp.c
        ${CMAKE_CURRENT_SOURCE_DIR}/src/http_parser.c
)

# Link kritis3m_applications_common against the http library
target_link_libraries(kritis3m-http-libs PRIVATE kritis3m_applications_common)

# Set compile definition of ENABLE_HTTPS option if activated
if (ENABLE_HTTPS)
    target_compile_definitions(kritis3m-http-libs PRIVATE ENABLE_HTTPS)
endif()

# Specify include directories for the kritis3m-http-libs
target_include_directories(kritis3m-http-libs PUBLIC
        $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include>
        $<INSTALL_INTERFACE:include>
)