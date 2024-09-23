add_library(kritis3m_service STATIC
        ${CMAKE_CURRENT_SOURCE_DIR}/src/kritis3m_scale_service.c
        ${CMAKE_CURRENT_SOURCE_DIR}/src/kritis3m_application_manager.c
        ${CMAKE_CURRENT_SOURCE_DIR}/src/hb_service.c
        ${CMAKE_CURRENT_SOURCE_DIR}/src/kritis3m_distribution_service.c
        ${CMAKE_CURRENT_SOURCE_DIR}/src/kritis3m_configuration.c

        # ${CMAKE_CURRENT_SOURCE_DIR}/src/zephyr_timerfd.c


)

# Public include directories
target_include_directories(kritis3m_service PUBLIC
        ${CMAKE_CURRENT_SOURCE_DIR}/include
)

# Link the common KRITIS3M application library
target_link_libraries(kritis3m_service PRIVATE kritis3m_applications_tcp_client_stdin_bridge)
target_link_libraries(kritis3m_service PRIVATE kritis3m_applications_echo_server)
target_link_libraries(kritis3m_service PRIVATE kritis3m_applications_proxy)
target_link_libraries(kritis3m_service PRIVATE kritis3m_applications_common)
target_link_libraries(kritis3m_service PRIVATE kritis3m_http_libs)

