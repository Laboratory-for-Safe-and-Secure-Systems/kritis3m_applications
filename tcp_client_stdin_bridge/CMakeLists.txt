
# Define the library
add_library(kritis3m_applications_tcp_client_stdin_bridge STATIC
        ${CMAKE_CURRENT_SOURCE_DIR}/src/tcp_client_stdin_bridge.c
)

# Public include directories
target_include_directories(kritis3m_applications_tcp_client_stdin_bridge PUBLIC
        ${CMAKE_CURRENT_SOURCE_DIR}/include
)

# Link the common KRITIS3M application library
target_link_libraries(kritis3m_applications_tcp_client_stdin_bridge PRIVATE kritis3m_applications_common)
