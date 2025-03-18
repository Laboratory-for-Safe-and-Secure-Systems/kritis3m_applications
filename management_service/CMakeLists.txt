# Definition of KRITIS3M scale service
add_library(kritis3m_service STATIC
        ${CMAKE_CURRENT_SOURCE_DIR}/src/kritis3m_scale_service.c
        ${CMAKE_CURRENT_SOURCE_DIR}/src/kritis3m_application_manager.c
        ${CMAKE_CURRENT_SOURCE_DIR}/src/kritis3m_configuration.c
        ${CMAKE_CURRENT_SOURCE_DIR}/src/configuration_parser.c
        ${CMAKE_CURRENT_SOURCE_DIR}/src/control_plane_conn.c
        ${CMAKE_CURRENT_SOURCE_DIR}/src/ipc.c
        ${CMAKE_CURRENT_SOURCE_DIR}/src/pki_client.c
        # ${CMAKE_CURRENT_SOURCE_DIR}/src/zephyr_timerfd.c
)

# Link the http library against the kritis3m_service
target_link_libraries(kritis3m_service PRIVATE kritis3m-http-libs)

# Public include directories
target_include_directories(kritis3m_service PUBLIC
        ${CMAKE_CURRENT_SOURCE_DIR}/include
        $<INSTALL_INTERFACE:include/kritis3m-http-libs>
)

# Link the common KRITIS3M application library
target_link_libraries(kritis3m_service PUBLIC kritis3m_applications_common)
target_link_libraries(kritis3m_service PUBLIC kritis3m_applications_echo_server)
target_link_libraries(kritis3m_service PUBLIC kritis3m_applications_tcp_client_stdin_bridge)
target_link_libraries(kritis3m_service PUBLIC kritis3m_applications_proxy)
target_link_libraries(kritis3m_service PUBLIC kritis3m_applications_network_tester)

find_package(Threads REQUIRED)
target_link_libraries(kritis3m_service PRIVATE Threads::Threads)




