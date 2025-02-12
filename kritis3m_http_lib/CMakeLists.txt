
# Enable HTTPS functionality. This requires to link against the kritis3m_asl library!
option(ENABLE_HTTPS "Enables Certificat Verification in HTTP(S) requests" ON)

# Make sure all libraries are installed in the lib directory (not lib64)
set(CMAKE_INSTALL_LIBDIR "lib")

# Set the output directories for libraries and executables
set(CMAKE_ARCHIVE_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/lib)
set(CMAKE_LIBRARY_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/lib)
set(CMAKE_RUNTIME_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/bin)


add_library(kritis3m-http-libs
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

install(TARGETS kritis3m-http-libs
        EXPORT kritis3m-http-libs-export
        LIBRARY DESTINATION ${CMAKE_INSTALL_LIBDIR}
        ARCHIVE DESTINATION ${CMAKE_INSTALL_LIBDIR}
        RUNTIME DESTINATION ${CMAKE_INSTALL_BINDIR}
)

# Install headers from the kritis3m-quest lib
install(DIRECTORY library/include/ DESTINATION include/kritis3m-http-libs)

# Install CMake configuration files so other CMake projects can find this library
install(EXPORT kritis3m-http-libs-export
        DESTINATION ${CMAKE_INSTALL_LIBDIR}/cmake/kritis3m-http-libs
        FILE kritis3m-http-libs-export.cmake
)
export(EXPORT kritis3m-http-libs-export
       FILE kritis3m-http-libs-export.cmake
)

include(CMakePackageConfigHelpers)
configure_package_config_file(${CMAKE_CURRENT_SOURCE_DIR}/cmake/kritis3m-http-libs-config.cmake.in
        ${CMAKE_CURRENT_BINARY_DIR}/kritis3m-http-libs-config.cmake
        INSTALL_DESTINATION ${CMAKE_INSTALL_LIBDIR}/cmake/kritis3m-http-libs
        NO_SET_AND_CHECK_MACRO
        NO_CHECK_REQUIRED_COMPONENTS_MACRO
)

install(FILES ${CMAKE_CURRENT_BINARY_DIR}/kritis3m-http-libs-config.cmake
        DESTINATION ${CMAKE_INSTALL_LIBDIR}/cmake/kritis3m-http-libs
)