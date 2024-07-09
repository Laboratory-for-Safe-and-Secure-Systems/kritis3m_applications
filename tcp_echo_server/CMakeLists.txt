
# Define the library
add_library(kritis3m_applications_tcp_echo_server STATIC
        ${CMAKE_CURRENT_SOURCE_DIR}/src/tcp_echo_server.c
)

# Public include directories
target_include_directories(kritis3m_applications_tcp_echo_server PUBLIC
        ${CMAKE_CURRENT_SOURCE_DIR}/include
)

# Link the common KRITIS3M application library
target_link_libraries(kritis3m_applications_tcp_echo_server PRIVATE kritis3m_applications_common)

# Link the library to the main target
target_link_libraries(${TARGET} PRIVATE kritis3m_applications_tcp_echo_server)
