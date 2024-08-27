
# Define the library
add_library(kritis3m_applications_echo_server STATIC
        ${CMAKE_CURRENT_SOURCE_DIR}/src/echo_server.c
)

# Public include directories
target_include_directories(kritis3m_applications_echo_server PUBLIC
        ${CMAKE_CURRENT_SOURCE_DIR}/include
)

# Link the common KRITIS3M application library
target_link_libraries(kritis3m_applications_echo_server PRIVATE kritis3m_applications_common)
