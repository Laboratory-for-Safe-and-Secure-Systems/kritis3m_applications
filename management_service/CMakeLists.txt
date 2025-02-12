# Neccessary Includes
include(GNUInstallDirs)
include(FetchContent)
set(FETCHCONTENT_QUIET FALSE)
set(CMAKE_EXPORT_COMPILE_COMMANDS ON)

enable_language(C)


# Add kritis3m_http_libs to the repository
FetchContent_Declare(kritis3m-http-libs
                GIT_REPOSITORY          git@github.com:Laboratory-for-Safe-and-Secure-Systems/kritis3m_http_lib.git
                GIT_TAG                 dev_https
                GIT_PROGRESS            TRUE
        )

        set(BUILD_SHARED_LIBS ON)

        FetchContent_GetProperties(kritis3m-http-libs)
        if(NOT kritis3m-http-libs_POPULATED)
                FetchContent_Populate(kritis3m-http-libs)
                add_subdirectory(${kritis3m-http-libs_SOURCE_DIR} ${kritis3m-http-libs_BINARY_DIR})
        endif()

add_library(kritis3m_service STATIC
        ${CMAKE_CURRENT_SOURCE_DIR}/src/kritis3m_scale_service.c
        ${CMAKE_CURRENT_SOURCE_DIR}/src/kritis3m_application_manager.c
        ${CMAKE_CURRENT_SOURCE_DIR}/src/kritis3m_configuration.c
        ${CMAKE_CURRENT_SOURCE_DIR}/src/configuration_parser.c
        ${CMAKE_CURRENT_SOURCE_DIR}/src/http_service.c

        # ${CMAKE_CURRENT_SOURCE_DIR}/src/zephyr_timerfd.c


)

# Link kritis3m_applications_common against the http library
target_link_libraries(kritis3m-http-libs PRIVATE kritis3m_applications_common)

# Link the http library against the kritis3m_service
target_link_libraries(kritis3m_service PRIVATE kritis3m-http-libs)

# Public include directories
target_include_directories(kritis3m_service PUBLIC
        ${CMAKE_CURRENT_SOURCE_DIR}/include
        $<INSTALL_INTERFACE:include/kritis3m-http-libs>
)


# Link the common KRITIS3M application library
target_link_libraries(kritis3m_service PRIVATE kritis3m_applications_common)
target_link_libraries(kritis3m_service PUBLIC kritis3m_applications_common)
target_link_libraries(kritis3m_service PUBLIC kritis3m_applications_echo_server)
target_link_libraries(kritis3m_service PUBLIC kritis3m_applications_tcp_client_stdin_bridge)
target_link_libraries(kritis3m_service PUBLIC kritis3m_applications_proxy)
target_link_libraries(kritis3m_service PUBLIC kritis3m_applications_network_tester)

find_package(Threads REQUIRED)
target_link_libraries(kritis3m_service PRIVATE Threads::Threads)




